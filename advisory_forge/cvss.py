"""CVSS 3.1 base scoring and severity classification.

The 3.1 implementation follows the equations, metric weights, and Roundup
function defined by FIRST's CVSS v3.1 specification.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, ROUND_CEILING, ROUND_HALF_UP
from typing import Mapping


CVSS31_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
CVSS31_VALUES: Mapping[str, frozenset[str]] = {
    "AV": frozenset("NALP"),
    "AC": frozenset("LH"),
    "PR": frozenset("NLH"),
    "UI": frozenset("NR"),
    "S": frozenset("UC"),
    "C": frozenset("HLN"),
    "I": frozenset("HLN"),
    "A": frozenset("HLN"),
}

# FIRST CVSS v3.1 Table 14: Base metrics.
_ATTACK_VECTOR = {"N": Decimal("0.85"), "A": Decimal("0.62"), "L": Decimal("0.55"), "P": Decimal("0.2")}
_ATTACK_COMPLEXITY = {"L": Decimal("0.77"), "H": Decimal("0.44")}
# Privileges Required has a Scope-dependent weight.
_PRIVILEGES = {
    "U": {"N": Decimal("0.85"), "L": Decimal("0.62"), "H": Decimal("0.27")},
    "C": {"N": Decimal("0.85"), "L": Decimal("0.68"), "H": Decimal("0.5")},
}
_USER_INTERACTION = {"N": Decimal("0.85"), "R": Decimal("0.62")}
_IMPACT = {"H": Decimal("0.56"), "L": Decimal("0.22"), "N": Decimal("0")}


@dataclass(frozen=True)
class CVSSResult:
    """A normalized CVSS vector and its calculated score."""

    version: str
    vector: str
    score: float
    severity: str


class CVSSValidationError(ValueError):
    """Raised when a CVSS vector is malformed or semantically invalid."""


def severity(score: float) -> str:
    """Return the FIRST qualitative severity band for *score*."""
    if not 0 <= score <= 10:
        raise ValueError("score must be between 0.0 and 10.0")
    if score == 0:
        return "None"
    if score < 4:
        return "Low"
    if score < 7:
        return "Medium"
    if score < 9:
        return "High"
    return "Critical"


def _roundup(value: Decimal) -> Decimal:
    """FIRST CVSS Roundup: smallest one-decimal number >= value."""
    if value <= 0:
        return Decimal("0.0")
    return (value * 10).quantize(Decimal("1"), rounding=ROUND_CEILING) / 10


def parse_cvss31(vector: str) -> dict[str, str]:
    """Validate a CVSS 3.1 base vector and return its metric/value mapping.

    The canonical ``CVSS:3.1/`` prefix is optional so short command-line input
    remains convenient. Temporal and Environmental metrics are intentionally
    rejected: this package calculates the Base Score.
    """
    if not isinstance(vector, str):
        raise CVSSValidationError("CVSS vector must be a string")

    compact = "/".join(vector.strip().split())
    prefix = "CVSS:3.1/"
    if compact.startswith(prefix):
        compact = compact[len(prefix) :]
    if not compact:
        raise CVSSValidationError("CVSS 3.1 vector is empty")

    parts = compact.split("/")
    if len(parts) != len(CVSS31_METRICS):
        raise CVSSValidationError(
            f"CVSS 3.1 base vector must contain exactly {len(CVSS31_METRICS)} metrics"
        )

    parsed: dict[str, str] = {}
    for expected, part in zip(CVSS31_METRICS, parts, strict=True):
        if ":" not in part:
            raise CVSSValidationError(f"metric {expected!r} has no value")
        metric, value = part.split(":", 1)
        if metric != expected:
            raise CVSSValidationError(
                f"metric order should be {'/'.join(CVSS31_METRICS)}; expected {expected!r}, got {metric!r}"
            )
        if value not in CVSS31_VALUES[metric]:
            allowed = ", ".join(sorted(CVSS31_VALUES[metric]))
            raise CVSSValidationError(f"invalid value {value!r} for metric {metric!r} (allowed: {allowed})")
        parsed[metric] = value
    return parsed


def score_cvss31(vector: str) -> CVSSResult:
    """Calculate the CVSS 3.1 Base Score using the FIRST equations."""
    m = parse_cvss31(vector)
    scope_changed = m["S"] == "C"

    iss = 1 - (1 - _IMPACT[m["C"]]) * (1 - _IMPACT[m["I"]]) * (1 - _IMPACT[m["A"]])
    if scope_changed:
        impact = Decimal("7.52") * (iss - Decimal("0.029")) - Decimal("3.25") * (iss - Decimal("0.02")) ** 15
    else:
        impact = Decimal("6.42") * iss

    exploitability = (
        Decimal("8.22")
        * _ATTACK_VECTOR[m["AV"]]
        * _ATTACK_COMPLEXITY[m["AC"]]
        * _PRIVILEGES[m["S"]][m["PR"]]
        * _USER_INTERACTION[m["UI"]]
    )

    if impact <= 0:
        score_decimal = Decimal("0.0")
    elif scope_changed:
        score_decimal = min(Decimal("1.08") * (impact + exploitability), Decimal("10"))
    else:
        score_decimal = min(impact + exploitability, Decimal("10"))
    score_decimal = _roundup(score_decimal)
    normalized = "CVSS:3.1/" + "/".join(f"{metric}:{m[metric]}" for metric in CVSS31_METRICS)
    score = float(score_decimal)
    return CVSSResult("3.1", normalized, score, severity(score))


# CVSS 4.0 follows FIRST's MacroVector equivalence classes and interpolation
# algorithm. The macro lookup table is kept in cvss4_data.py.
from itertools import product  # noqa: E402

from advisory_forge.cvss4_data import MACRO_VECTOR_SCORES  # noqa: E402


CVSS4_ORDER = (
    "AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA",
    "E", "CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI",
    "MVC", "MVI", "MVA", "MSC", "MSI", "MSA",
    "S", "AU", "R", "V", "RE", "U",
)
CVSS4_REQUIRED = CVSS4_ORDER[:11]
CVSS4_VALUES: dict[str, frozenset[str]] = {
    "AV": frozenset("NALP"),
    "AC": frozenset("LH"),
    "AT": frozenset("NP"),
    "PR": frozenset("NLH"),
    "UI": frozenset("NPA"),
    "VC": frozenset("HLN"),
    "VI": frozenset("HLN"),
    "VA": frozenset("HLN"),
    "SC": frozenset("HLN"),
    "SI": frozenset("SHLN"),
    "SA": frozenset("SHLN"),
    "E": frozenset("XUPA"),
    "CR": frozenset("XHML"),
    "IR": frozenset("XHML"),
    "AR": frozenset("XHML"),
    "MAV": frozenset("XNALP"),
    "MAC": frozenset("XLH"),
    "MAT": frozenset("XNP"),
    "MPR": frozenset("XNLH"),
    "MUI": frozenset("XNPA"),
    "MVC": frozenset("XHLN"),
    "MVI": frozenset("XHLN"),
    "MVA": frozenset("XHLN"),
    "MSC": frozenset("XHLN"),
    "MSI": frozenset("XSHLN"),
    "MSA": frozenset("XSHLN"),
    "S": frozenset("XPN"),
    "AU": frozenset("XYN"),
    "R": frozenset("XIA"),
    "V": frozenset("XDC"),
    "RE": frozenset("XLMH"),
    "U": frozenset({"X", "Clear", "Green", "Amber", "Red"}),
}

# Ordered severity levels for interpolation distances. Lower is more severe.
_LEVELS = {
    "AV": {"N": 0, "A": 1, "L": 2, "P": 3},
    "PR": {"N": 0, "L": 1, "H": 2},
    "UI": {"N": 0, "P": 1, "A": 2},
    "AC": {"L": 0, "H": 1},
    "AT": {"N": 0, "P": 1},
    "VC": {"H": 0, "L": 1, "N": 2},
    "VI": {"H": 0, "L": 1, "N": 2},
    "VA": {"H": 0, "L": 1, "N": 2},
    "SC": {"H": 1, "L": 2, "N": 3},
    "SI": {"S": 0, "H": 1, "L": 2, "N": 3},
    "SA": {"S": 0, "H": 1, "L": 2, "N": 3},
    "CR": {"H": 0, "M": 1, "L": 2},
    "IR": {"H": 0, "M": 1, "L": 2},
    "AR": {"H": 0, "M": 1, "L": 2},
    "E": {"A": 0, "P": 1, "U": 2},
}

# Highest-severity metric combinations for each MacroVector component.
_MAX_COMPOSED = {
    1: {
        0: ("AV:N/PR:N/UI:N/",),
        1: ("AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"),
        2: ("AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"),
    },
    2: {
        0: ("AC:L/AT:N/",),
        1: ("AC:H/AT:N/", "AC:L/AT:P/"),
    },
    3: {
        (0, 0): ("VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/",),
        (0, 1): ("VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"),
        (1, 0): ("VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"),
        (1, 1): (
            "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/",
            "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
            "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
            "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
            "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
        ),
        (2, 1): ("VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/",),
    },
    4: {
        0: ("SC:H/SI:S/SA:S/",),
        1: ("SC:H/SI:H/SA:H/",),
        2: ("SC:L/SI:L/SA:L/",),
    },
    5: {0: ("E:A/",), 1: ("E:P/",), 2: ("E:U/",)},
}

# Maximum severity depth in each MacroVector component.
_MAX_SEVERITY = {
    1: {0: 1, 1: 4, 2: 5},
    2: {0: 1, 1: 2},
    3: {(0, 0): 7, (0, 1): 6, (1, 0): 8, (1, 1): 8, (2, 1): 10},
    4: {0: 6, 1: 5, 2: 4},
    5: {0: 1, 1: 1, 2: 1},
}


def parse_cvss4(vector: str) -> dict[str, str]:
    """Validate a CVSS 4.0 vector and return its present metric values."""
    if not isinstance(vector, str):
        raise CVSSValidationError("CVSS vector must be a string")
    compact = "/".join(vector.strip().split())
    prefix = "CVSS:4.0/"
    if not compact.startswith(prefix):
        raise CVSSValidationError("CVSS 4.0 vector must begin with CVSS:4.0/")
    compact = compact[len(prefix) :]
    if not compact:
        raise CVSSValidationError("CVSS 4.0 vector has no metrics")

    parsed: dict[str, str] = {}
    order_index = 0
    for part in compact.split("/"):
        if ":" not in part:
            raise CVSSValidationError(f"metric segment {part!r} has no value")
        metric, value = part.split(":", 1)
        if not metric:
            raise CVSSValidationError("metric abbreviation is empty")
        if metric not in CVSS4_VALUES:
            raise CVSSValidationError(f"{metric!r} is not a valid CVSS 4.0 metric abbreviation")
        if metric in parsed:
            raise CVSSValidationError(f"metric {metric!r} is defined more than once")
        allowed = CVSS4_VALUES[metric]
        if value not in allowed:
            rendered = ", ".join(sorted(allowed))
            raise CVSSValidationError(f"invalid value {value!r} for metric {metric!r} (allowed: {rendered})")
        try:
            metric_index = CVSS4_ORDER.index(metric)
        except ValueError as exc:  # pragma: no cover - guarded above
            raise CVSSValidationError(f"{metric!r} is not a valid CVSS 4.0 metric") from exc
        if metric_index < order_index:
            raise CVSSValidationError(f"fixed CVSS 4.0 metric order is not respected at {metric!r}")
        order_index = metric_index + 1
        parsed[metric] = value

    missing = [metric for metric in CVSS4_REQUIRED if metric not in parsed]
    if missing:
        rendered = ", ".join(missing)
        raise CVSSValidationError(f"mandatory CVSS 4.0 metric(s) missing: {rendered}")
    return parsed


def _effective4(parsed: dict[str, str], metric: str) -> str:
    if metric not in parsed:
        if metric == "E":
            return "A"
        if metric in {"CR", "IR", "AR"}:
            return "H"
        return "X"
    value = parsed[metric]
    # CVSS 4.0 defaults these to the highest-severity value.
    if metric == "E" and value == "X":
        return "A"
    if metric in {"CR", "IR", "AR"} and value == "X":
        return "H"
    if metric in {"MSI", "MSA"}:
        return value
    modified = parsed.get("M" + metric)
    if modified is not None and modified != "X":
        return modified
    return value


def _macro_vector(parsed: dict[str, str]) -> str:
    def m(metric: str) -> str:
        return _effective4(parsed, metric)

    if m("AV") == "N" and m("PR") == "N" and m("UI") == "N":
        eq1 = 0
    elif (m("AV") == "N" or m("PR") == "N" or m("UI") == "N") and not (
        m("AV") == "N" and m("PR") == "N" and m("UI") == "N"
    ) and m("AV") != "P":
        eq1 = 1
    else:
        eq1 = 2

    eq2 = 0 if m("AC") == "L" and m("AT") == "N" else 1

    if m("VC") == "H" and m("VI") == "H":
        eq3 = 0
    elif m("VC") == "H" or m("VI") == "H" or m("VA") == "H":
        eq3 = 1
    else:
        eq3 = 2

    if m("MSI") == "S" or m("MSA") == "S":
        eq4 = 0
    elif m("SC") == "H" or m("SI") == "H" or m("SA") == "H":
        eq4 = 1
    else:
        eq4 = 2

    eq5 = {"A": 0, "P": 1, "U": 2}[m("E")]

    if (
        (m("CR") == "H" and m("VC") == "H")
        or (m("IR") == "H" and m("VI") == "H")
        or (m("AR") == "H" and m("VA") == "H")
    ):
        eq6 = 0
    else:
        eq6 = 1
    return f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"


def _fragment_values(fragment: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for pair in fragment.rstrip("/").split("/"):
        metric, value = pair.split(":", 1)
        values[metric] = value
    return values


def _score_to_one_decimal(value: float) -> float:
    # JavaScript's Math.round rounds positive halves upward.
    return float(Decimal(str(value)).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


def score_cvss4(vector: str) -> CVSSResult:
    """Calculate a CVSS 4.0 score using FIRST MacroVector interpolation."""
    parsed = parse_cvss4(vector)

    if all(_effective4(parsed, metric) == "N" for metric in ("VC", "VI", "VA", "SC", "SI", "SA")):
        score = 0.0
        normalized = "CVSS:4.0/" + "/".join(f"{m}:{parsed[m]}" for m in CVSS4_ORDER if m in parsed)
        return CVSSResult("4.0", normalized, score, severity(score))

    macro = _macro_vector(parsed)
    if macro not in MACRO_VECTOR_SCORES:
        raise RuntimeError(f"FIRST MacroVector {macro} has no published score")
    value = MACRO_VECTOR_SCORES[macro]
    eq1, eq2, eq3, eq4, eq5, eq6 = map(int, macro)

    # Find a highest-severity vector from which the selected vector can be
    # reached by non-negative stepwise changes.
    combinations = product(
        _MAX_COMPOSED[1][eq1],
        _MAX_COMPOSED[2][eq2],
        _MAX_COMPOSED[3][(eq3, eq6)],
        _MAX_COMPOSED[4][eq4],
        _MAX_COMPOSED[5][eq5],
    )
    selected_max: dict[str, str] | None = None
    for combination in combinations:
        candidate = _fragment_values("".join(combination))
        if all(
            metric not in _LEVELS or _LEVELS[metric][_effective4(parsed, metric)] >= _LEVELS[metric][value_max]
            for metric, value_max in candidate.items()
        ):
            selected_max = candidate
            break
    if selected_max is None:
        raise RuntimeError(f"could to find a highest-severity vector for MacroVector {macro}")

    def distance(metric: str) -> float:
        return float(_LEVELS[metric][_effective4(parsed, metric)] - _LEVELS[metric][selected_max[metric]])

    distance_eq1 = distance("AV") + distance("PR") + distance("UI")
    distance_eq2 = distance("AC") + distance("AT")
    distance_eq3eq6 = sum(distance(metric) for metric in ("VC", "VI", "VA", "CR", "IR", "AR"))
    distance_eq4 = distance("SC") + distance("SI") + distance("SA")
    current_distances = (distance_eq1, distance_eq2, distance_eq3eq6, distance_eq4, 0.0)

    def lower(key: str) -> float | None:
        return MACRO_VECTOR_SCORES.get(key)

    # Change one MacroVector component at a time. EQ3 and EQ6 must be jointly
    # lowered according to the transition table in the specification.
    eq36_key: str | tuple[str, str]
    if eq3 == 0 and eq6 == 0:
        left = f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}"
        right = f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}"
        candidates = [lower(left), lower(right)]
        eq36_score = max((x for x in candidates if x is not None), default=None)
    elif (eq3 == 1 and eq6 == 1) or (eq3 == 0 and eq6 == 1) or (eq3 == 1 and eq6 == 0):
        special = eq3 + 1 if eq3 in (0, 1) and eq6 == 1 else eq6 + 1
        eq36_key = f"{eq1}{eq2}{eq3}{eq4}{eq5}{special}"
        eq36_score = lower(eq36_key)
    else:
        eq36_key = f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6 + 1}"
        eq36_score = lower(eq36_key)

    lower_scores = (
        lower(f"{eq1 + 1}{eq2}{eq3}{eq4}{eq5}{eq6}"),
        lower(f"{eq1}{eq2 + 1}{eq3}{eq4}{eq5}{eq6}"),
        eq36_score,
        lower(f"{eq1}{eq2}{eq3}{eq4 + 1}{eq5}{eq6}"),
        lower(f"{eq1}{eq2}{eq3}{eq4}{eq5 + 1}{eq6}"),
    )
    max_depths = (
        float(_MAX_SEVERITY[1][eq1]),
        float(_MAX_SEVERITY[2][eq2]),
        float(_MAX_SEVERITY[3][(eq3, eq6)]),
        float(_MAX_SEVERITY[4][eq4]),
        float(_MAX_SEVERITY[5][eq5]),
    )

    normalized_distances: list[float] = []
    for current, lower_score, depth in zip(current_distances, lower_scores, max_depths, strict=True):
        if lower_score is None or depth == 0:
            continue
        normalized_distances.append((value - lower_score) * current / depth)
    mean_distance = sum(normalized_distances) / len(normalized_distances) if normalized_distances else 0.0
    score = _score_to_one_decimal(min(max(value - mean_distance, 0.0), 10.0))

    normalized = "CVSS:4.0/" + "/".join(f"{m}:{parsed[m]}" for m in CVSS4_ORDER if m in parsed)
    return CVSSResult("4.0", normalized, score, severity(score))

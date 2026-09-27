"""CVSS 3.1 base scoring and severity classification.

The 3.1 implementation follows the equations, metric weights, and Roundup
function defined by FIRST's CVSS v3.1 specification.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, ROUND_CEILING
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

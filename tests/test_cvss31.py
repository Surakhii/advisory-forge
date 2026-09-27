import pytest

from advisory_forge.cvss import (
    CVSSValidationError,
    parse_cvss31,
    score_cvss31,
    severity,
)


# FIRST, "CVSS Examples", document version 1.8 (2026-09).
# https://www.first.org/cvss/examples
FIRST_CVSS31_EXAMPLES = [
    ("CVE-2022-41741", 7.0, "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    ("CVE-2021-44714", 3.3, "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    ("CVE-2022-21830", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    ("CVE-2022-22186", 7.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N"),
    ("CVE-2023-21989", 6.0, "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N"),
    ("CVE-2020-3947", 9.3, "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    ("CVE-2023-48228", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"),
    ("CVE-2023-30560", 6.8, "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("CVE-2014-0160", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    ("CVE-2021-44228", 10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    ("CVE-2014-6271", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("CVE-2013-6014", 9.3, "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H"),
    ("CVE-2016-5729", 8.2, "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H"),
    ("CVE-2015-2890", 6.0, "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H"),
    ("CVE-2018-3652", 7.6, "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    ("CVE-2024-6387", 8.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("CVE-2023-30545", 6.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
    ("CVE-2021-23846", 5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    ("CVE-2022-24682", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    ("CVE-2020-0926", 5.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"),
    ("CVE-2024-55228", 9.0, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H"),
    ("CVE-2023-5602", 4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"),
    ("CVE-2022-20759", 8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    ("CVE-2023-28311", 7.8, "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"),
    ("CVE-2022-22965", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("CVE-2022-20826", 6.4, "CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("CVE-2022-21500", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    ("CVE-2021-32570", 4.9, "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N"),
    ("CVE-2022-26134", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("CVE-2023-20245", 5.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N"),
    ("CVE-2024-1233", 7.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"),
    ("CVE-2022-47379", 8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
]


@pytest.mark.parametrize(("name", "expected_score", "vector"), FIRST_CVSS31_EXAMPLES, ids=[x[0] for x in FIRST_CVSS31_EXAMPLES])
def test_first_official_cvss31_examples(name: str, expected_score: float, vector: str) -> None:
    result = score_cvss31(vector)
    assert result.score == expected_score
    assert result.vector == vector


def test_prefix_is_optional_and_vector_is_normalized() -> None:
    assert score_cvss31("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N").vector == (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    )


@pytest.mark.parametrize(
    ("vector", "message_part"),
    [
        ("", "empty"),
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", "exactly 8"),
        ("AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "invalid value 'X' for metric 'AV'"),
        ("AC:L/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H", "metric order"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F", "exactly 8"),
    ],
)
def test_invalid_cvss31_vectors(vector: str, message_part: str) -> None:
    with pytest.raises(CVSSValidationError, match=message_part):
        score_cvss31(vector)


def test_parser_returns_metrics() -> None:
    parsed = parse_cvss31("AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:H")
    assert parsed == {"AV": "A", "AC": "H", "PR": "L", "UI": "R", "S": "C", "C": "L", "I": "N", "A": "H"}


@pytest.mark.parametrize(
    ("score", "expected"),
    [(0.0, "None"), (3.9, "Low"), (4.0, "Medium"), (6.9, "Medium"), (7.0, "High"), (9.0, "Critical")],
)
def test_severity_bands(score: float, expected: str) -> None:
    assert severity(score) == expected


def test_no_impact_scores_zero() -> None:
    result = score_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N")
    assert result.score == 0.0
    assert result.severity == "None"

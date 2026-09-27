import pytest

from advisory_forge.cvss import CVSSValidationError, score_cvss4
from advisory_forge.cvss4_data import MACRO_VECTOR_SCORES


# FIRST, "CVSS Examples", document version 1.8 (2026-09).
# https://www.first.org/cvss/examples
FIRST_CVSS4_EXAMPLES = [
    ("CVE-2022-41741", 7.3, "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
    ("CVE-2021-44714", 4.6, "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"),
    ("CVE-2022-21830", 5.1, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N"),
    ("CVE-2022-22186", 6.9, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N"),
    ("CVE-2023-21989", 5.9, "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N"),
    ("CVE-2020-3947", 9.4, "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"),
    ("CVE-2023-48228", 9.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:H/SI:H/SA:H"),
    ("CVE-2023-30560", 8.3, "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:H/SA:N/S:P/V:D"),
    ("CVE-2026-48172", 10.0, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A"),
    ("CVE-2014-0160", 8.7, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:A"),
    ("CVE-2021-44228", 9.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A"),
    ("CVE-2021-44228-BTE", 5.5, "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/MAC:L/MAT:N/MVC:N/MVI:N/MVA:L"),
    ("CVE-2014-6271", 9.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A"),
    ("CVE-2013-6014", 6.4, "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:H/SI:N/SA:H"),
    ("CVE-2016-5729", 8.4, "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/R:I"),
    ("CVE-2015-2890", 7.1, "CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/R:I"),
    ("CVE-2018-3652", 7.0, "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
    ("CVE-2024-6387", 8.2, "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P"),
    ("CVE-2024-6387-BTE", 5.5, "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/MAC:L/MAT:N/MVC:N/MVI:N/MVA:L"),
    ("CVE-2023-30545", 7.1, "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"),
    ("CVE-2021-23846", 8.2, "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"),
    ("CVE-2023-22394", 8.7, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L"),
    ("CVE-2023-22394-BTE", 6.6, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L/E:U/MVA:H/MSA:N"),
    ("CVE-2020-0926", 5.1, "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N"),
    ("CVE-2024-55228", 8.5, "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:H/VI:H/VA:H/SC:L/SI:L/SA:N"),
    ("CVE-2023-5602", 5.1, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N"),
    ("CVE-2022-20759", 7.7, "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
    ("CVE-2022-20826", 5.4, "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
    ("CVE-2023-20245", 2.7, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:L/SA:N/E:U/CR:L/IR:L/AR:L"),
    ("CVE-2022-47379", 9.4, "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/S:P/AU:Y/V:C/RE:L"),
]


@pytest.mark.parametrize(("name", "expected_score", "vector"), FIRST_CVSS4_EXAMPLES, ids=[x[0] for x in FIRST_CVSS4_EXAMPLES])
def test_first_official_cvss4_examples(name: str, expected_score: float, vector: str) -> None:
    result = score_cvss4(vector)
    assert result.score == expected_score
    assert result.vector == vector


def test_first_macro_vector_table_is_complete() -> None:
    assert len(MACRO_VECTOR_SCORES) == 270


def test_no_impact_cvss4_scores_zero() -> None:
    result = score_cvss4("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N")
    assert result.score == 0.0
    assert result.severity == "None"


@pytest.mark.parametrize(
    ("vector", "message_part"),
    [
        ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", "begin with CVSS:4.0/"),
        ("CVSS:4.0/AV:F/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N", "invalid value 'F'"),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/SC:N/SI:N/SA:N", "mandatory"),
        ("CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N", "fixed CVSS 4.0 metric order"),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N/E:A/E:X", "defined more than once"),
    ],
)
def test_invalid_cvss4_vectors(vector: str, message_part: str) -> None:
    with pytest.raises(CVSSValidationError, match=message_part):
        score_cvss4(vector)

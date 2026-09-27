from pathlib import Path

import pytest

from advisory_forge.scaffold import create_advisory, package_advisory


def test_create_advisory_builds_expected_files(tmp_path: Path) -> None:
    target = create_advisory(
        "ssrf-report",
        cwe=918,
        title="Server-side request forgery in downloader",
        output_root=tmp_path,
    )
    assert [path.name for path in sorted(target.iterdir())] == [
        "ghsa-checklist.md", "report.md", "vendor-email.md"
    ]
    report = (target / "report.md").read_text()
    assert "# Server-side request forgery in downloader" in report
    assert "**CWE:** CWE-918" in report
    for heading in (
        "## Affected software", "## Vulnerability details", "## Impact",
        "## Reproduction steps", "## Remediation", "## Credit", "## Disclosure timeline",
    ):
        assert heading in report
    assert "```text" in report
    assert "CWE-918" in (target / "vendor-email.md").read_text()


def test_reported_date_inserts_dated_timeline(tmp_path: Path) -> None:
    target = create_advisory("dated", cwe=79, title="XSS", output_root=tmp_path, reported="2026-03-30")
    report = (target / "report.md").read_text()
    assert "| 2026-04-06 | +7d |" in report
    assert "REPORTED_DATE" not in report


def test_existing_advisory_is_not_overwritten(tmp_path: Path) -> None:
    create_advisory("exists", cwe=79, title="XSS", output_root=tmp_path)
    with pytest.raises(FileExistsError):
        create_advisory("exists", cwe=79, title="Changed", output_root=tmp_path)
    assert "# XSS" in (tmp_path / "exists" / "report.md").read_text()


@pytest.mark.parametrize("directory", ["../escape", "with/slash", "", "."])
def test_unsafe_directory_names_are_rejected(tmp_path: Path, directory: str) -> None:
    with pytest.raises(ValueError):
        create_advisory(directory, cwe=79, title="XSS", output_root=tmp_path)


@pytest.mark.parametrize("cwe", [0, -1])
def test_cwe_must_be_positive(tmp_path: Path, cwe: int) -> None:
    with pytest.raises(ValueError):
        create_advisory("bad-cwe", cwe=cwe, title="XSS", output_root=tmp_path)


def test_package_combines_all_submission_documents(tmp_path: Path) -> None:
    target = create_advisory("bundle-me", cwe=918, title="SSRF", output_root=tmp_path)
    (target / "notes.md").write_text("# Additional notes\n")
    output = package_advisory(target)
    text = output.read_text()
    assert output == target / "advisory-bundle.md"
    assert "# SSRF" in text
    assert "Coordinated disclosure: SSRF" in text
    assert "# GHSA submission checklist" in text
    assert "# Additional notes" in text

    package_advisory(target)
    assert output.read_text().count("# GHSA submission checklist") == 1


def test_package_requires_report(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        package_advisory(tmp_path)

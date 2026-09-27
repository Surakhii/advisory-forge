import pytest

from advisory_forge.cli import main


def test_cli_scores_cvss31(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["cvss", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"]) == 0
    captured = capsys.readouterr()
    assert captured.out == "9.8 Critical\nCVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n"


def test_cli_scores_cvss4(capsys: pytest.CaptureFixture[str]) -> None:
    vector = "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    assert main(["cvss", "--four", vector]) == 0
    assert "7.3 High" in capsys.readouterr().out


def test_cli_cvss_requires_exactly_one_vector(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["cvss"]) == 2
    assert "provide either" in capsys.readouterr().err


def test_cli_reports_invalid_cvss(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["cvss", "AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"]) == 1
    assert "invalid value" in capsys.readouterr().err


def test_cli_renders_timeline(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["timeline", "--reported", "2026-03-30"]) == 0
    output = capsys.readouterr().out
    assert "| 2026-04-06 | +7d |" in output
    assert "| 2026-06-28 | +90d |" in output


def test_cli_init_and_package(tmp_path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["init", "my-advisory", "--cwe", "918", "--title", "SSRF", "--reported", "2026-03-30"]) == 0
    assert (tmp_path / "my-advisory" / "report.md").is_file()
    assert main(["package", "my-advisory"]) == 0
    assert (tmp_path / "my-advisory" / "advisory-bundle.md").is_file()
    assert "created" in capsys.readouterr().out


def test_cli_init_error_is_clean(tmp_path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "exists").mkdir()
    assert main(["init", "exists", "--cwe", "79", "--title", "XSS"]) == 1
    assert "already exists" in capsys.readouterr().err

"""Advisory directory scaffolding and submission packaging."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path
import re

from advisory_forge.timeline import generate_timeline, render_timeline


_TEMPLATE_FILES = ("report.md", "vendor-email.md", "ghsa-checklist.md")


def _template(name: str) -> str:
    return (files("advisory_forge") / "templates" / name).read_text(encoding="utf-8")


def create_advisory(
    directory: str,
    *,
    cwe: int,
    title: str,
    output_root: str | Path = ".",
    reported: str | None = None,
    force: bool = False,
) -> Path:
    """Create an advisory directory from the bundled templates."""
    if not directory or Path(directory).name != directory or directory in {".", ".."}:
        raise ValueError("directory must be a non-empty name without path separators")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", directory):
        raise ValueError("directory may contain letters, digits, dots, underscores, and hyphens only")
    if cwe <= 0:
        raise ValueError("cwe must be a positive integer")
    if not title.strip():
        raise ValueError("title must not be empty")

    target = Path(output_root) / directory
    if target.exists():
        if not force:
            raise FileExistsError(f"advisory directory already exists: {target}")
        if not target.is_dir():
            raise ValueError(f"advisory target is not a directory: {target}")
    else:
        target.mkdir(parents=True, mode=0o755)

    replacements = {
        "{{ title }}": title.strip(),
        "{{ cwe }}": str(cwe),
        # Do not imply that a local tool reserved CVE or GHSA identifiers.
        "{{ advisory_id }}": "PENDING",
    }
    for template_name in _TEMPLATE_FILES:
        rendered = _template(template_name)
        for placeholder, value in replacements.items():
            rendered = rendered.replace(placeholder, value)
        if template_name == "report.md" and reported is not None:
            rendered = rendered.replace(
                "| REPORTED_DATE | Report sent to vendor |\n",
                render_timeline(generate_timeline(reported)) + "\n",
            )
        (target / template_name).write_text(rendered, encoding="utf-8")
    return target


def package_advisory(directory: str | Path) -> Path:
    """Combine an advisory into one Markdown file suitable for submission."""
    root = Path(directory)
    if not root.is_dir():
        raise FileNotFoundError(f"advisory directory does not exist: {root}")
    report_path = root / "report.md"
    if not report_path.is_file():
        raise FileNotFoundError(f"required advisory report is missing: {report_path}")

    output = root / "advisory-bundle.md"
    ordered_names = ["report.md", "vendor-email.md", "ghsa-checklist.md"]
    included = set(ordered_names) | {output.name}
    sections: list[str] = []
    for name in ordered_names:
        path = root / name
        if path.is_file():
            sections.append(path.read_text(encoding="utf-8").strip())
    for path in sorted(root.glob("*.md")):
        if path.name not in included:
            sections.append(path.read_text(encoding="utf-8").strip())
            included.add(path.name)

    output.write_text("\n\n---\n\n".join(sections) + "\n", encoding="utf-8")
    return output

"""Command-line interface for advisory-forge."""

from __future__ import annotations

import argparse
import sys

from advisory_forge import __version__
from advisory_forge.cvss import CVSSValidationError, score_cvss31, score_cvss4
from advisory_forge.scaffold import create_advisory, package_advisory
from advisory_forge.timeline import generate_timeline, render_timeline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="forge",
        description="Scaffold and manage coordinated-disclosure advisories.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="create an advisory directory")
    init.add_argument("advisory", help="advisory directory name")
    init.add_argument("--cwe", required=True, type=int, help="CWE number, for example 918")
    init.add_argument("--title", required=True, help="vulnerability title")
    init.add_argument("--reported", help="initial report date in YYYY-MM-DD format")
    init.add_argument("--force", action="store_true", help="overwrite files in an existing advisory directory")

    cvss = subparsers.add_parser("cvss", help="validate and score a CVSS vector")
    cvss.add_argument("vector", nargs="?", help="CVSS 3.1 base vector")
    cvss.add_argument("--four", metavar="VECTOR", help="CVSS 4.0 vector")

    timeline = subparsers.add_parser("timeline", help="render disclosure milestones")
    timeline.add_argument("--reported", required=True, help="initial report date in YYYY-MM-DD format")
    timeline.add_argument("--publication-days", type=int, default=90, help="embargo length (default: 90)")

    package = subparsers.add_parser("package", help="combine an advisory into one Markdown file")
    package.add_argument("advisory", help="advisory directory")
    return parser


def _run(args: argparse.Namespace) -> int:
    if args.command == "init":
        target = create_advisory(
            args.advisory,
            cwe=args.cwe,
            title=args.title,
            reported=args.reported,
            force=args.force,
        )
        print(f"created {target}")
        return 0

    if args.command == "cvss":
        if bool(args.vector) == bool(args.four):
            print("error: provide either a 3.1 vector or --four VECTOR", file=sys.stderr)
            return 2
        result = score_cvss4(args.four) if args.four else score_cvss31(args.vector)
        print(f"{result.score:.1f} {result.severity}")
        print(result.vector)
        return 0

    if args.command == "timeline":
        print(render_timeline(generate_timeline(args.reported, args.publication_days)))
        return 0

    output = package_advisory(args.advisory)
    print(f"packaged {output}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return _run(args)
    except (CVSSValidationError, ValueError, FileNotFoundError, FileExistsError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

# SPEC: advisory-forge

CLI that scaffolds and manages coordinated-disclosure vulnerability
advisories: the unglamorous paperwork of responsible security research,
productized.

## Architecture (Python 3.11+, MIT license)

```
advisory_forge/
  __init__.py
  cli.py          # argparse subcommands: init, cvss, timeline, package
  scaffold.py     # builds advisory dir from template + answers
  cvss.py         # CVSS 3.1 base-score implementation (the real equation
                  # from the FIRST spec) + severity bands + vector
                  # validation; CVSS 4.0 via the official macro approach
  timeline.py     # disclosure timeline block generator with escalation
                  # reminder dates (e.g. 7/14/30/90 day milestones)
  templates/      # markdown advisory template, vendor email draft,
                  # GHSA-style submission checklist
tests/
pyproject.toml    # pip install -e . -> console script "forge"
```

## Subcommands

- `forge init my-advisory --cwe 918 --title "..."` -> creates
  my-advisory/ with report.md skeleton (sections: summary, affected
  software table, vulnerability details with root-cause code block,
  impact, reproduction steps, remediation, credit, disclosure timeline)
  + vendor-email.md draft.
- `forge cvss "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"` -> validates the
  3.1 vector, prints score + severity band. Implement the actual 3.1
  equation (weight tables, roundup function per spec) NOT a lookup table.
- `forge cvss --four "CVSS:4.0/AV:N/..."` -> 4.0 scoring.
- `forge timeline --reported 2026-03-30` -> renders dated milestones
  (ack expected +7d, fix nudge +14d, publication +90d, etc).
- `forge package my-advisory` -> single-file markdown bundle for
  submission (GHSA / vendor sec@ email ready).

## Quality bar

pytest MUST include the FIRST-published CVSS 3.1 example vectors as a
known-answer test suite (at least 15 vectors with official scores).
README with the disclosure philosophy (90-day default, no 0day drops,
vendor grace) + quickstart. Clean git history.

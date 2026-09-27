# advisory-forge

`advisory-forge` is a small, local-first CLI for the unglamorous paperwork in
coordinated vulnerability disclosure. It scaffolds technical reports and vendor
emails, scores CVSS 3.1 and 4.0 vectors, generates an escalation timeline, and
bundles the final package into one Markdown file suitable for GHSA or a
`security@` submission.

## Disclosure philosophy

- **Private report first.** Technical details go to the vendor's security
  channel before they go anywhere public.
- **Ninety days by default.** The clock starts on the initial report. A fixed
  default creates pressure without turning coordination into an indefinite
  silence tax.
- **No 0day drops.** This tool is not a publication-delay bypass. It does not
  publish anything itself and its templates assume an embargo.
- **Vendor grace is earned by progress.** A concrete remediation plan, regular
  updates, or a genuinely difficult deployment can justify more time. Ignoring
  the report does not.
- **Public interest can change the calculation.** Active exploitation or a
  rapidly spreading incident may justify earlier defensive guidance. That is a
  decision to document explicitly, not a template checkbox.
- **Proofs stay proportional.** Include enough detail to verify and fix the
  issue, not a turnkey attack against unpatched users.

## Quickstart

Requires Python 3.11 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
pytest
```

Create an advisory:

```bash
forge init cloudreve-ssrf \
  --cwe 918 \
  --title "Server-side request forgery in remote download" \
  --reported 2026-03-30
```

This creates `cloudreve-ssrf/` with `report.md`, `vendor-email.md`, and
`ghsa-checklist.md`.

Score a CVSS 3.1 vector:

```bash
forge cvss "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
```

Output:

```text
9.8 Critical
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

Score CVSS 4.0:

```bash
forge cvss --four "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
```

Generate dated milestones and escalation reminders:

```bash
forge timeline --reported 2026-03-30
```

Package the finished advisory:

```bash
forge package cloudreve-ssrf
```

The bundle is written to `cloudreve-ssrf/advisory-bundle.md`.

## CVSS implementation

CVSS 3.1 implements the FIRST specification equations directly: metric weight
tables, the changed/unchanged Impact equations, Exploitability, and the
Roundup function. It accepts Base vectors only.

CVSS 4.0 implements FIRST's MacroVector equivalence classes and interpolation
algorithm. Threat and Environmental metrics affect the calculated score when
present; Supplemental metrics are validated but intentionally do not affect it.
The 270-entry MacroVector score table comes from FIRST's reference calculator.

The test suite checks 32 FIRST-published CVSS 3.1 example vectors and 30
FIRST-published CVSS 4.0 examples. FIRST requires publishing a score together
with its vector; the CLI therefore always returns both.

## Project layout

```text
advisory_forge/
  cli.py         argparse CLI: init, cvss, timeline, package
  cvss.py        CVSS 3.1 equations and CVSS 4.0 MacroVector interpolation
  cvss4_data.py  FIRST's 270 MacroVector scores
  scaffold.py    template rendering and bundle packaging
  timeline.py    7/14/30/60/90-day milestone generator
  templates/     report, vendor email, and GHSA checklist
tests/           unit, CLI, and FIRST known-answer tests
```

## License

MIT. See [LICENSE](LICENSE.md).

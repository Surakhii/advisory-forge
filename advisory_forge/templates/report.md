# {{ title }}

**Status:** Draft
**CWE:** CWE-{{ cwe }}
**Advisory ID:** {{ advisory_id }}

## Summary

Describe the vulnerability in two or three precise sentences. State what the
attacker can do, not merely where the problematic code lives.

## Affected software

| Product | Version range | Status | Notes |
|---|---|---|---|
| PRODUCT | 0.0.0 through 1.2.3 | Affected | |
| PRODUCT | 2.0.0 | Not affected | Fix released |

## Vulnerability details

Explain the security boundary that fails and the conditions required for
exploitation. Keep exploitation prerequisites explicit.

### Root cause

```text
Replace this block with the smallest relevant source excerpt or pseudocode.
Explain the missing validation, unsafe operation, or authorization failure.
```

## Impact

State the practical confidentiality, integrity, and availability impact to the
vulnerable system. If impact crosses into a subsequent system, explain the
trust boundary and that system separately.

## Reproduction steps

1. Prepare a representative test environment. Do not test against third-party
   production systems without written authorization.
2. Trigger the vulnerable operation with a harmless proof of concept.
3. Record the observed result and the expected security behavior.

## Remediation

- Describe the primary fix, not only a workaround.
- Include upgrade guidance and migration notes for affected deployments.
- Add a separately described mitigation where no immediate upgrade is possible.

## Credit

Reported by RESEARCHER_NAME.

## Disclosure timeline

| Date | Event |
|---|---|
| REPORTED_DATE | Report sent to vendor |

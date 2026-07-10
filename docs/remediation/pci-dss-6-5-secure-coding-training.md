# Developers receive secure-coding training at least annually

`PCI-DSS-6.5-secure-coding-training` · framework **pci-dss** · severity **medium** · Develop and Maintain Secure Systems and Software

## What this control checks

PCI DSS Requirement 6.5 requires software-development personnel who work
on bespoke and custom software to be trained at least once every 12 months
in secure software design and secure coding techniques, including how to
prevent common software attacks (under PCI DSS v4.0 this is Requirement
6.2.2). Concord reads a cosigned attestation of the secure-coding training
program, held under version control in GitHub, and verifies it names the
training program, the security topics covered (for example the OWASP Top
10), how completion is tracked, and the date training was last delivered.
The attestation must be signed and the most recent delivery must be within
the last 365 days.

## Why it matters

Most application-layer vulnerabilities that expose cardholder data, such
as injection and broken access control, originate in code written by
developers who were never trained to avoid them. Requiring documented,
annually refreshed secure-coding training that explicitly covers the OWASP
Top 10 and secure handling of cardholder data raises the baseline of every
engineer touching the environment, and requiring completion tracking makes
coverage auditable rather than aspirational. Concord denies the control
when training has lapsed beyond one year, when required program details are
missing, or when the attestation is unsigned, because stale or unverifiable
training gives false assurance that developers are current on today's
threats.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no secure-coding-training attestation collected
- no secure-coding-training attestation document found at the configured repository path
- secure-coding-training attestation missing required field: <value>
- secure-coding-training attestation signature did not verify
- secure-coding training last delivered <value>, exceeding the <value>-day annual training interval

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-6.5-secure-coding-training
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss: ["6.5", "6.2.2"]
  soc2: ["CC1.4"]
  nist_800_53: ["AT-3", "SA-11"]
  iso27001: ["A.6.3", "A.8.28"]
```

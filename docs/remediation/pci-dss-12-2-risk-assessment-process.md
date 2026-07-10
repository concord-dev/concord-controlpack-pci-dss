# A targeted risk-assessment process is documented and performed at least annually

`PCI-DSS-12.2-risk-assessment-process` · framework **pci-dss** · severity **high** · Maintain an Information Security Policy

## What this control checks

PCI DSS Requirement 12.2 requires that acceptable use and, more broadly,
the organization's risk-assessment process be defined, documented, and
performed so that risks to the cardholder data environment are identified,
analyzed, and tracked to remediation at least once every 12 months and upon
significant change. Concord evaluates a signed, version-controlled
attestation of the risk-assessment program. The attestation must be
current, cosign-verified, describe the methodology and the scope assessed,
record when the last assessment was performed, and confirm that identified
findings are tracked.

## Why it matters

A risk assessment that happened once and was never repeated is exactly what
Requirement 12.2 exists to prevent — threats, the cardholder data flow, and
the environment all change, and a stale assessment gives false assurance.
QSAs ask for the methodology, the scope, the date of the most recent
assessment, and evidence that findings were driven to closure. Concord
enforces all four, including a freshness check that fails an assessment
older than 12 months rather than accepting a document that merely exists.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no risk-assessment-process attestation found (expected a signed attestation at policies/governance/risk-assessment-process.yaml)
- no risk-assessment-process attestation document found (expected a signed attestation at policies/governance/risk-assessment-process.yaml)
- risk-assessment-process attestation is missing required field <value>
- risk-assessment-process attestation must confirm findings_tracked = true (identified risks driven to remediation)
- risk assessment last performed <value> days ago — PCI DSS Requirement 12.2 expects an assessment at least every 12 months
- risk-assessment-process attestation cosign signature did not verify

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-12.2-risk-assessment-process
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss:
  - "12.2"
  soc2:
  - "CC3.1"
  - "CC3.2"
  - "CC9.2"
  nist_800_53:
  - "RA-3"
  - "PM-9"
  iso27001:
  - "A.5.4"
```

# Visitors are identified, escorted, and logged within the cardholder data environment

`PCI-DSS-9.2-visitor-identification` · framework **pci-dss** · severity **medium** · Implement Strong Access Control Measures

## What this control checks

PCI DSS Requirement 9.2 requires physical access controls that manage
entry into facilities and systems containing cardholder data, including
the handling of visitors who must be identified before being granted
access, escorted at all times within the cardholder data environment, and
recorded in a visitor log. Reception desks and paper or badge visitor logs
are not observable as cloud telemetry, so Concord evaluates a signed,
version-controlled attestation of the visitor-management program. The
attestation must be current, cosign-verified, and describe how visitors are
identified, the escort policy that applies inside the CDE, and how long the
visitor log is retained.

## Why it matters

Unescorted or unrecorded visitors are one of the most common physical
findings a QSA raises, because a visitor with unsupervised access to the
cardholder data environment can tamper with devices, read screens, or
remove media without any trace. PCI DSS expects visitors to be
distinguishable from personnel, escorted throughout, and captured in a log
retained for at least three months. Forcing those commitments into a
signed, annually reviewed artifact gives the assessor evidence the program
exists and is maintained rather than assumed.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no visitor-identification attestation found (expected a signed attestation at policies/physical/visitor-management.yaml)
- no visitor-identification attestation document found (expected a signed attestation at policies/physical/visitor-management.yaml)
- visitor-identification attestation is missing required field <value>
- visitor-identification attestation last reviewed <value> days ago — PCI DSS Requirement 9.2 expects review at least every 12 months
- visitor-identification attestation cosign signature did not verify

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-9.2-visitor-identification
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss:
  - "9.2"
  - "9.3"
  soc2:
  - "CC6.4"
  nist_800_53:
  - "PE-2"
  - "PE-3"
  - "PE-8"
  iso27001:
  - "A.7.2"
  - "A.7.6"
```

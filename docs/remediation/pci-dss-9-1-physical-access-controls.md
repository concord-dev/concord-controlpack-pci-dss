# Physical access to systems storing cardholder data is restricted and logged

`PCI-DSS-9.1-physical-access-controls` · framework **pci-dss** · severity **high** · Implement Strong Access Control Measures

## What this control checks

PCI DSS Requirement 9.1 requires that physical access to the systems,
facilities, and media that store, process, or transmit cardholder data be
restricted to authorized personnel and that entry be monitored. Badge
readers, locked cages, and CCTV are not reachable as cloud telemetry, so
Concord evaluates a signed, version-controlled attestation of the physical
access program. The attestation must be current, cosign-verified, and
enumerate the access-control measures in force, the roles authorized for
entry, and how physical access is logged and retained.

## Why it matters

Physical access to servers, network closets, or backup media that hold
cardholder data bypasses every logical safeguard protecting that data, and
QSAs routinely test Requirement 9 by asking who can enter the cardholder
data environment and how that entry is recorded. A documented,
owner-attested program that names the authorized roles, the enforcing
controls, and the access-log retention period gives the assessor a single
source of truth and forces the program to be re-reviewed at least annually.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no physical-access-controls attestation found (expected a signed attestation at policies/physical/physical-access-controls.yaml)
- no physical-access-controls attestation document found (expected a signed attestation at policies/physical/physical-access-controls.yaml)
- physical-access-controls attestation is missing required field <value>
- physical-access-controls attestation last reviewed <value> days ago — PCI DSS Requirement 9.1 expects review at least every 12 months
- physical-access-controls attestation cosign signature did not verify

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-9.1-physical-access-controls
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss:
  - "9.1"
  - "9.2.1"
  soc2:
  - "CC6.4"
  nist_800_53:
  - "PE-2"
  - "PE-3"
  - "PE-6"
  iso27001:
  - "A.7.1"
  - "A.7.2"
```

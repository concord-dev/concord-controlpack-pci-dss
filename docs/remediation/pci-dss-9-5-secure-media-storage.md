# Media containing cardholder data is stored securely with periodic inventory

`PCI-DSS-9.5-secure-media-storage` · framework **pci-dss** · severity **medium** · Implement Strong Access Control Measures

## What this control checks

PCI DSS Requirement 9.5 requires that media containing cardholder data —
backup tapes, removable drives, and printed reports — be physically secured
and strictly controlled, including periodic inventories so that any loss or
theft is detected. Physical media handling is not observable through cloud
APIs, so Concord evaluates a signed, version-controlled attestation of the
media-storage program. The attestation must be current, cosign-verified,
describe the storage controls in force and the inventory cadence, and record
when the last inventory was performed.

## Why it matters

Media is the classic PCI blind spot: a backup tape in an unlocked cabinet
or an uninventoried drive is cardholder data walking out the door with no
logical control able to stop it. QSAs test Requirement 9.5 by asking to see
the media inventory and the date it was last reconciled. Concord enforces
both the existence of storage controls and a fresh inventory (within the
last 12 months), so a program that was set up once and never re-inventoried
fails rather than passing on paper.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no secure-media-storage attestation found (expected a signed attestation at policies/physical/media-storage.yaml)
- no secure-media-storage attestation document found (expected a signed attestation at policies/physical/media-storage.yaml)
- secure-media-storage attestation is missing required field <value>
- secure-media-storage attestation last reviewed <value> days ago — PCI DSS Requirement 9.5 expects review at least every 12 months
- secure-media-storage inventory last performed <value> days ago — PCI DSS Requirement 9.5 expects a periodic (at least annual) media inventory
- secure-media-storage attestation cosign signature did not verify

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-9.5-secure-media-storage
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss:
  - "9.5"
  soc2:
  - "CC6.4"
  - "CC6.5"
  nist_800_53:
  - "MP-2"
  - "MP-4"
  - "MP-6"
  iso27001:
  - "A.7.10"
  - "A.8.10"
```

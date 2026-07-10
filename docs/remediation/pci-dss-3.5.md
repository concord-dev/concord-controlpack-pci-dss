# KMS keys protecting cardholder data rotate at least annually

`PCI-DSS-3.5-encryption-key-management` · framework **pci-dss** · severity **critical** · Protect Cardholder Data

## What this control checks

PCI DSS v4.0 Requirement 3.5 requires PAN to be unreadable wherever it
is stored, including via cryptography with strong key management.
Specifically 3.6.1 + 3.6.4 require key rotation at defined intervals
(annually is the de-facto minimum auditors accept). Concord verifies
every KMS key tagged pci=true has rotation enabled and a rotation
cadence of <= 365 days.

## Why it matters

Stale keys are the most common PCI 3.x audit finding — they're
operationally invisible, so without automated tracking the org has no
way to demonstrate compliance.

## Evidence

Collected from the `aws` source (`kms_keys` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no KMS evidence collected
- PCI key <value> has rotation disabled
- PCI key <value> rotates every <value> days (>365)
- PCI key <value> is pending deletion — confirm cardholder data is not still encrypted with it

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-3.5-encryption-key-management
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss:
  - "3.5"
  - "3.6.1"
  - "3.6.4"
  soc2:
  - "C1.1"
```

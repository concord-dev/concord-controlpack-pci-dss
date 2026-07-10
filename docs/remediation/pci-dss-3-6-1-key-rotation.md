# Cryptographic keys protecting stored account data are rotated at least annually

`PCI-DSS-3.6.1-key-rotation` · framework **pci-dss** · severity **high** · Protect Cardholder Data

## What this control checks

PCI DSS v4.0 Requirement 3.6.1 requires cryptographic keys used to
protect stored account data to be secured, and Requirement 3.7.4
requires those keys to be changed once they reach the end of their
defined cryptoperiod — a period auditors expect to be no longer than
one year. Concord inspects every AWS KMS key tagged pci=true and
confirms automatic rotation is enabled, the configured rotation period
is within 365 days, and the key was actually rotated within the last
year.

## Why it matters

Lapsed key rotation is one of the most frequently missed PCI
Requirement 3 findings because it is operationally invisible: a key
that has stopped rotating keeps encrypting and decrypting data with no
outward symptom, so the gap only surfaces during a formal assessment.
Evaluating rotation fail-closed — treating any key whose rotation
cannot be positively confirmed as within the window as non-compliant —
ensures the control never grants false assurance from absent or
incomplete telemetry.

## Evidence

Collected from the `aws` source (`kms_keys` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- PCI DSS 3.6.1: no KMS key evidence collected
- PCI DSS 3.6.1: key <value> does not have automatic rotation enabled
- PCI DSS 3.6.1: key <value> rotates every <value> days, exceeding the <value>-day maximum
- PCI DSS 3.6.1: key <value> has not been rotated within the last <value> days (last_rotated_at=<value>)
- PCI DSS 3.6.1: key <value> is pending deletion — confirm no stored account data still depends on it

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-3.6.1-key-rotation
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss:
  - "3.6.1"
  - "3.7.4"
  nist_800_53:
  - "SC-12"
  iso27001:
  - "A.8.24"
  soc2:
  - "C1.1"
```

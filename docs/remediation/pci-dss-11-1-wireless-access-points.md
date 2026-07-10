# Wireless access points are tested at least quarterly to detect rogues

`PCI-DSS-11.1-wireless-access-points` · framework **pci-dss** · severity **medium** · Regularly Monitor and Test Networks

## What this control checks

PCI DSS Requirement 11.1 requires processes and mechanisms to test for the
presence of unauthorized (rogue) wireless access points at least once every
three months, and to identify and respond to any that are found. Because
rogue-AP detection is a physical and RF activity with no cloud telemetry,
Concord evaluates a signed structured attestation of the testing program. The
attestation must declare the test cadence, the date of the last test, the
detection methodology, and the responsible role, must be no older than 92
days, and must carry a verified signature.

## Why it matters

An unauthorized wireless access point plugged into the cardholder data
environment bypasses every perimeter control, so PCI DSS mandates recurring
detection on a quarterly cadence. There is no AWS or code-repository signal
that evidences a physical wireless sweep, so a structured, signed attestation
from an accountable owner is the appropriate and auditable control. Concord
enforces that the attestation is complete, recent (within one quarter), on an
acceptable cadence, and cryptographically signed, so a stale, unsigned, or
incomplete statement cannot pass and give false assurance.

## Evidence

Collected from the `attestation` source (`structured_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no rogue wireless access-point testing attestation submitted
- rogue-AP testing attestation is missing required field <value> (PCI DSS Requirement 11.1)
- rogue-AP testing cadence <value> is less frequent than the required quarterly schedule (PCI DSS Requirement 11.1)
- last rogue-AP test was <value> days ago, exceeding the <value>-day (quarterly) maximum (PCI DSS Requirement 11.1)
- rogue-AP testing attestation is not signed or its signature could not be verified (PCI DSS Requirement 11.1)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-11.1-wireless-access-points
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss: ["11.1", "11.1.1", "11.1.2"]
  soc2: ["CC7.1"]
  nist_800_53: ["SI-4", "AC-18"]
```

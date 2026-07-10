# IDS/IPS monitors traffic across every active region of the CDE

`PCI-DSS-11.4-intrusion-detection` · framework **pci-dss** · severity **high** · Regularly Monitor and Test Networks

## What this control checks

PCI DSS Requirement 11.4 requires intrusion-detection and/or
intrusion-prevention techniques to detect and alert on intrusions into the
network, monitoring traffic at the perimeter and at critical points of the
cardholder data environment. Concord verifies that AWS GuardDuty, which
performs network and threat detection on VPC flow, DNS, and CloudTrail
telemetry, has an enabled detector in every active region. Each active region
without an enabled detector is reported separately.

## Why it matters

Intrusion detection only provides assurance if it covers the entire attack
surface; a single region without an enabled GuardDuty detector is a blind
spot where malicious traffic and credential abuse go unnoticed. GuardDuty is
a regional service, so coverage must be confirmed region by region against
the set of regions actually in use, and a detector that exists but is
suspended provides no monitoring. Concord fails closed when no evidence is
collected or when no active region is reported, because absence of coverage
must never be read as compliance.

## Evidence

Collected from the `aws` source (`guardduty_status` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no intrusion-detection evidence collected
- no active regions reported; IDS/IPS coverage of the CDE cannot be verified — failing closed (PCI DSS Requirement 11.4)
- GuardDuty (IDS/IPS) is not enabled in active region <value> that carries CDE traffic (PCI DSS Requirement 11.4)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **30m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-11.4-intrusion-detection
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss: ["11.4", "11.4.1"]
  soc2: ["CC7.1", "CC7.2"]
  nist_800_53: ["SI-4", "SC-7"]
  cis_aws: ["3.8"]
```

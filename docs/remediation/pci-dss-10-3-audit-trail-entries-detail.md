# Audit-trail entries record user, timestamp, event, origin, and are tamper-evident

`PCI-DSS-10.3-audit-trail-entries-detail` · framework **pci-dss** · severity **high** · Regularly Monitor and Test Networks

## What this control checks

PCI DSS Requirement 10.3 requires each audit-trail entry to record the user
identification, type of event, date and time, success or failure indication,
origination of the event, and the identity of affected data or resources.
Concord verifies the CloudTrail configuration flags that make these fields
complete and trustworthy: global service events must be included so user
identity and origin are recorded for IAM and STS actions, management events
must be recorded so the event source and name are captured, and log-file
validation must be enabled so entries are tamper-evident. The check fails
closed when no trail is present.

## Why it matters

CloudTrail records the six required fields in every event, but only when the
trail is configured to capture the relevant activity and to protect the
integrity of what it records. A trail that excludes global service events
silently drops the user identity and origin for IAM, STS, and other global
actions; a trail without management events omits the event source and name;
and a trail without log-file validation cannot prove its entries were not
altered after the fact, which undermines their evidentiary value. Because an
incomplete or unverifiable entry cannot satisfy Requirement 10.3, Concord
fails closed if any of these flags is missing.

## Evidence

Collected from the `aws` source (`audit_trail_status` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no audit-trail evidence collected
- no CloudTrail trail present; audit-trail entry detail cannot be verified — failing closed (PCI DSS Requirement 10.3)
- CloudTrail trail <value> excludes global service events; user identity and origin for IAM/STS actions are not recorded (PCI DSS Requirement 10.3.1)
- CloudTrail trail <value> does not record management events; event source and name are not captured (PCI DSS Requirement 10.3.1)
- CloudTrail trail <value> has log-file validation disabled; audit-trail entries are not tamper-evident (PCI DSS Requirement 10.3.2)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **30m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-10.3-audit-trail-entries-detail
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss: ["10.3", "10.3.1", "10.3.2"]
  soc2: ["CC7.2", "CC7.3"]
  nist_800_53: ["AU-3", "AU-9"]
  cis_aws: ["3.2"]
```

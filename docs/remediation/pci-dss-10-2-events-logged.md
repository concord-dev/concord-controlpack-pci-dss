# Required events are logged for read, write, and data-plane activity

`PCI-DSS-10.2-events-logged` · framework **pci-dss** · severity **high** · Regularly Monitor and Test Networks

## What this control checks

PCI DSS Requirement 10.2 requires audit logs to capture the events needed
to detect and investigate anomalous activity, including all individual user
access, all actions taken by privileged accounts, and access to audit data.
Concord verifies that AWS CloudTrail records management events for both read
and write activity and that at least one data-event selector is configured so
that data-plane access (for example, S3 object reads) to cardholder data is
captured. Each missing event category is reported separately.

## Why it matters

Requirement 10.2 enumerates the specific event categories that must be
logged; a trail that captures write actions but not read actions, or that
omits data-plane events entirely, leaves whole classes of activity invisible
to investigators. CloudTrail models this through event selectors:
management events with a read/write type of "All" cover privileged
control-plane actions in both directions, while data-event selectors capture
object-level access. Concord fails closed unless every required category is
covered, because a partial log cannot satisfy the forensic intent of the
requirement.

## Evidence

Collected from the `aws` source (`cloudtrail_event_selectors` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no CloudTrail event-selector evidence collected
- CloudTrail is not logging management (control-plane) read events; privileged read activity is not captured (PCI DSS Requirement 10.2.1)
- CloudTrail is not logging management (control-plane) write events; privileged change activity is not captured (PCI DSS Requirement 10.2.1)
- CloudTrail has no data-event selector; data-plane access to stored cardholder data is not captured (PCI DSS Requirement 10.2.1.1)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **30m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-10.2-events-logged
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss: ["10.2", "10.2.1", "10.2.1.1", "10.2.1.7"]
  soc2: ["CC7.2"]
  nist_800_53: ["AU-2", "AU-12"]
  cis_aws: ["3.1"]
```

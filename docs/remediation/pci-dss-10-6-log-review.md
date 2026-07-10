# Security events are reviewed through automated CloudWatch metric alarms

`PCI-DSS-10.6-log-review` · framework **pci-dss** · severity **high** · Regularly Monitor and Test Networks

## What this control checks

PCI DSS Requirement 10.6 requires that logs and security events be reviewed
to identify anomalies or suspicious activity, and permits automated
mechanisms to perform that review. Concord verifies that AWS CloudWatch
metric alarms exist for the required security-event categories (unauthorized
API calls, root-account usage, IAM policy changes, and failed console
sign-ins) and that each alarm has an active notification action so detected
events are surfaced to responders. Each uncovered category is reported
separately.

## Why it matters

Daily manual review of raw logs does not scale, so PCI DSS explicitly allows
automated log-review tools; CloudWatch metric filters paired with alarms are
the canonical AWS implementation and align with the CIS AWS Foundations
monitoring benchmarks. An alarm that exists but has no notification action is
equivalent to no review at all, because a triggered condition never reaches a
human, so Concord requires both an alarm and a wired-up action for every
required event category. Missing coverage of any category means a whole class
of suspicious activity would go unreviewed, so the control fails closed.

## Evidence

Collected from the `aws` source (`cloudwatch_metric_alarms` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no CloudWatch metric-alarm evidence collected
- no CloudWatch metric alarm with an active notification reviews security-event category <value> (PCI DSS Requirement 10.6)
- CloudWatch metric alarm <value> has no notification action; <value> events would not surface for review (PCI DSS Requirement 10.6.1)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **45m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-10.6-log-review
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss: ["10.6", "10.6.1"]
  soc2: ["CC7.2", "CC7.3"]
  nist_800_53: ["AU-6", "SI-4"]
  cis_aws: ["4.1", "4.3", "4.4"]
```

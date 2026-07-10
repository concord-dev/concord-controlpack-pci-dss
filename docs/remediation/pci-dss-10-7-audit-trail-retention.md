# Audit-log history is retained at least one year with three months immediately available

`PCI-DSS-10.7-audit-trail-retention` · framework **pci-dss** · severity **high** · Regularly Monitor and Test Networks

## What this control checks

PCI DSS Requirement 10.7 requires audit-trail history to be retained for at
least twelve months, with at least the most recent three months immediately
available for analysis. Concord verifies that every audit-log CloudWatch log
group has a retention period of at least 365 days, and that any S3 lifecycle
rule used for long-term log storage both expires objects no sooner than 365
days and keeps at least the most recent 90 days in immediately retrievable
storage rather than an archive tier. Each log group below the threshold is
reported separately.

## Why it matters

Retaining audit logs for a full year is what makes it possible to
investigate breaches that are frequently discovered months after they occur,
and keeping the most recent three months immediately available ensures
responders are not blocked waiting on archive restores during an active
incident. A CloudWatch log group with a short retention window silently
deletes history, and an S3 lifecycle rule that transitions objects to Glacier
too early defeats the immediate-availability requirement even if total
retention is long enough. Concord fails closed when no retention mechanism is
configured at all.

## Evidence

Collected from the `aws` source (`log_retention_status` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no audit-log retention evidence collected
- no audit-log retention mechanism configured (neither CloudWatch log-group retention nor an S3 lifecycle rule); failing closed (PCI DSS Requirement 10.7)
- audit log group <value> retains logs for <value> days, below the required <value> days (PCI DSS Requirement 10.7)
- S3 audit-log bucket <value> expires objects after <value> days, below the required <value> days (PCI DSS Requirement 10.7)
- S3 audit-log bucket <value> archives objects to cold storage after <value> days; at least <value> days must remain immediately available (PCI DSS Requirement 10.7)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **30m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-10.7-audit-trail-retention
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss: ["10.7", "10.5.1"]
  soc2: ["CC7.2"]
  nist_800_53: ["AU-11", "AU-4"]
  cis_aws: ["3.4"]
```

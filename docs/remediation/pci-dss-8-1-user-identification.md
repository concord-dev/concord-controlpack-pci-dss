# Every user is uniquely identified before access is granted

`PCI-DSS-8.1-user-identification` · framework **pci-dss** · severity **high** · Implement Strong Access Control Measures

## What this control checks

PCI DSS v4.0 Requirement 8.1/8.2.1 requires that all users are assigned a
unique ID before access to system components is granted, so that actions
can be traced to a known individual. Concord reads the AWS IAM credential
report and fails any console-enabled identity whose name matches a shared
or generic pattern (for example "admin", "shared", "service"), because
such accounts cannot attribute activity to one person. It also fails the
root account when it is used for routine operations, since day-to-day use
of root breaks individual accountability.

## Why it matters

Shared and generic logins are the classic way accountability collapses:
when several administrators sign in as "admin" no audit trail can place a
specific person at a specific action, defeating Requirements 8 and 10 at
once. The root account carries the same problem plus unlimited privilege,
so PCI expects it to be reserved for the rare tasks that require it rather
than routine work. The control fails closed: if the credential report is
absent it denies rather than assuming every identity is unique.

## Evidence

Collected from the `aws` source (`iam_credential_report` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no IAM credential report collected — cannot demonstrate that every user is uniquely identified (PCI DSS 8.1)
- IAM user <value> has a shared/generic name with console access — access must be tied to a unique, named individual (PCI DSS 8.1)
- root account was used <value> day(s) ago — root must not be used for routine operations, which breaks individual accountability (PCI DSS 8.1)
- root account has an active access key — root must have no standing credentials and must not be used routinely (PCI DSS 8.1)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-8.1-user-identification
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss:
  - "8.1"
  - "8.2.1"
  soc2:
  - "CC6.1"
  nist_800_53:
  - "IA-2"
  - "AC-2"
  cis_aws:
  - "1.7"
```

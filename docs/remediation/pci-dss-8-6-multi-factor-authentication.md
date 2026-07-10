# MFA is enforced for all non-console access into the cardholder data environment

`PCI-DSS-8.6-multi-factor-authentication` · framework **pci-dss** · severity **critical** · Implement Strong Access Control Measures

## What this control checks

PCI DSS v4.0 Requirement 8.6 (with 8.4.2 and 8.5.1) requires multi-factor
authentication for all access into the cardholder data environment,
including non-console and administrative access paths. Concord reads the
AWS IAM credential report and denies any identity that can reach the CDE
without a registered MFA device: a console-enabled user whose mfa_active
is not true, and a user that relies on an active long-lived access key
while the identity carries no MFA device. Missing MFA fields are treated
as no MFA so the control never fails open.

## Why it matters

Requirement 8.6 closes the gaps left by console-only MFA checks: attackers
increasingly pivot through long-lived access keys and other non-interactive
paths that never prompt for a second factor. By flagging both console
identities without MFA and identities whose only credential is an active
access key with no MFA device, Concord surfaces every unprotected route
into the CDE. The check fails closed on the second factor — an mfa_active
value that is false, null, or absent all deny, and an absent credential
report denies outright.

## Evidence

Collected from the `aws` source (`iam_credential_report` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no IAM credential report collected — cannot verify MFA on access into the CDE (PCI DSS 8.6)
- IAM user <value> has console access into the CDE with no active MFA device (PCI DSS 8.6)
- IAM user <value> reaches the CDE with an active access key but has no MFA device — non-console access must also be protected by MFA (PCI DSS 8.6)
- root account has console access without MFA — enable a hardware MFA device on root immediately

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-8.6-multi-factor-authentication
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss:
  - "8.6"
  - "8.4.2"
  - "8.5.1"
  soc2:
  - "CC6.1"
  nist_800_53:
  - "IA-2(1)"
  cis_aws:
  - "1.10"
```

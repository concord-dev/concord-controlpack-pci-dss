# Authentication uses at least two factors for remote and admin access

`PCI-DSS-8.2-strong-authentication-factors` · framework **pci-dss** · severity **critical** · Implement Strong Access Control Measures

## What this control checks

PCI DSS v4.0 Requirement 8.2 with 8.4.1 requires that authentication for
interactive access — and all remote and administrative access — is
established with at least two distinct factors. For AWS console access
that means a password (something you know) plus a registered MFA device
(something you have). Concord reads the IAM credential report and fails
any console-enabled, non-root identity whose mfa_active flag is not true,
which leaves the account protected by a single factor.

## Why it matters

Single-factor console access is the most common initial-access vector in
payment-environment breaches, and stolen or phished passwords are useless
to an attacker only when a second factor is required. The check fails
closed on the second factor: an mfa_active value that is false, null, or
absent all deny, so a truncated or partially collected credential report
can never be misread as "two factors present". The root account is
evaluated by Requirement 8.1 and surfaced here only as an advisory.

## Evidence

Collected from the `aws` source (`iam_credential_report` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no IAM credential report collected — cannot verify at least two authentication factors (PCI DSS 8.2)
- IAM user <value> has console (password) access with no active MFA device — PCI DSS 8.2 requires at least two authentication factors; enroll MFA
- root account has console access — evaluate under PCI DSS 8.1 and prefer federated administrative access

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-8.2-strong-authentication-factors
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss:
  - "8.2"
  - "8.4.1"
  soc2:
  - "CC6.1"
  nist_800_53:
  - "IA-2(1)"
  cis_aws:
  - "1.10"
```

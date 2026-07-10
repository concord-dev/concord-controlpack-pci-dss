# Access to system components is restricted by job classification and function

`PCI-DSS-7.1-need-to-know-access` · framework **pci-dss** · severity **high** · Implement Strong Access Control Measures

## What this control checks

PCI DSS v4.0 Requirement 7.1/7.2.1 requires that access to system
components and cardholder data is restricted to only the least privileges
necessary for an individual's job classification and function ("need to
know"). Concord reads every IAM identity (user, group, and role) together
with its attached managed and inline policies and fails any identity that
carries the AWS-managed AdministratorAccess policy or a statement allowing
Action "*" on Resource "*". A standing full-admin grant is broader than
any single job function requires and therefore cannot satisfy need-to-know.

## Why it matters

Broad "*/*" grants are the most common way least-privilege erodes: a role
created for one task accumulates AdministratorAccess and quietly becomes a
path to every cardholder-data store in the account. Qualified Security
Assessors treat an unconstrained admin grant attached to a routine
identity as an immediate Requirement 7 finding because it defeats the
ability to tie each permission back to a documented job function. The
check fails closed: when no IAM policy evidence is collected the control
denies rather than assuming least-privilege holds.

## Evidence

Collected from the `aws` source (`iam_policies` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no IAM policy evidence collected — cannot demonstrate that access is restricted to least privilege (PCI DSS 7.1)
- IAM <value> <value> is attached to AdministratorAccess — full-admin access is not restricted by job function (PCI DSS 7.1)
- IAM <value> <value> attaches policy <value> allowing Action "*" on Resource "*" — grant is broader than any job function requires (PCI DSS 7.1)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-7.1-need-to-know-access
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss:
  - "7.1"
  - "7.2.1"
  soc2:
  - "CC6.1"
  - "CC6.3"
  nist_800_53:
  - "AC-6"
  cis_aws:
  - "1.16"
```

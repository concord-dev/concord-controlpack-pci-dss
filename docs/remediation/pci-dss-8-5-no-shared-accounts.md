# Shared, group, or generic accounts are not used for system administration

`PCI-DSS-8.5-no-shared-accounts` · framework **pci-dss** · severity **high** · Implement Strong Access Control Measures

## What this control checks

PCI DSS v4.0 Requirement 8.5 (with 8.2.2) prohibits shared, group, or
generic accounts and passwords from being used to administer system
components or otherwise access the cardholder data environment. Concord
reads the AWS IAM credential report and fails any account whose name
matches a shared or generic pattern (for example "shared", "service",
"team", "admin") when that account still holds a live credential — an
enabled console password or an active access key. Such an account is a
usable, non-attributable identity and must be replaced with per-person
accounts.

## Why it matters

Shared administrative logins defeat accountability and cannot be revoked
for a single person when someone leaves, so a departing employee often
retains an active path into the environment. A generically named account
with a live access key is especially dangerous because it grants silent,
long-lived programmatic access that no individual owns. This control looks
beyond console logins to active access keys precisely to catch shared
service credentials. It fails closed: with no credential report it denies
rather than assuming no shared accounts exist.

## Evidence

Collected from the `aws` source (`iam_credential_report` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no IAM credential report collected — cannot verify that no shared or generic accounts are in use (PCI DSS 8.5)
- account <value> matches a shared/generic naming pattern and holds a live credential (<value>) — shared or group accounts must not be used, especially for administration (PCI DSS 8.5)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-8.5-no-shared-accounts
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss:
  - "8.5"
  - "8.2.2"
  soc2:
  - "CC6.1"
  nist_800_53:
  - "AC-2"
  - "IA-2"
  cis_aws:
  - "1.1"
```

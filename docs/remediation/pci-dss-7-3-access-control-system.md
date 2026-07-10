# Access control system covers all system components and defaults to deny-all

`PCI-DSS-7.3-access-control-system` · framework **pci-dss** · severity **high** · Implement Strong Access Control Measures

## What this control checks

PCI DSS v4.0 Requirement 7.3 requires access to system components and
cardholder data to be managed by an access-control system that covers all
components, assigns privileges by job classification, and is set to
"deny all" by default (7.3.3). Concord inspects the effect statements of
every attached IAM policy and fails any statement that subverts that
deny-by-default posture: an Allow of Action "*" on Resource "*"
(an explicit allow-all), or an Allow that uses NotAction or NotResource,
which inverts the model into "allow everything except" and re-opens the
default-deny baseline.

## Why it matters

AWS IAM is deny-by-default only until a single over-broad Allow statement
negates it. The two most dangerous patterns are an outright Allow of
"*"/"*" and the subtle Allow + NotAction/NotResource idiom, which grants
every action or resource except a short deny-list and therefore fails
open whenever a new service or resource appears. Assessors verifying 7.3.3
look precisely for statements that break the default-deny stance. The
control fails closed: with no policy evidence it denies rather than
presuming the access-control system defaults to deny.

## Evidence

Collected from the `aws` source (`iam_policies` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no IAM policy evidence collected — cannot verify the access-control system defaults to deny-all (PCI DSS 7.3)
- IAM <value> <value> policy <value> allows Action "*" on Resource "*" — an explicit allow-all defeats the required deny-all default (PCI DSS 7.3.3)
- IAM <value> <value> policy <value> uses Allow + NotAction — this allows every action except a deny-list and subverts deny-by-default (PCI DSS 7.3.3)
- IAM <value> <value> policy <value> uses Allow + NotResource — this allows access to every resource except a deny-list and subverts deny-by-default (PCI DSS 7.3.3)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-7.3-access-control-system
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss:
  - "7.3"
  - "7.3.3"
  soc2:
  - "CC6.1"
  - "CC6.3"
  nist_800_53:
  - "AC-3"
  - "AC-6"
  cis_aws:
  - "1.16"
```

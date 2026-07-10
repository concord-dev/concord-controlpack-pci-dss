# All system components produce audit trails that link actions to individual users

`PCI-DSS-10.1-audit-trail-implementation` · framework **pci-dss** · severity **high** · Regularly Monitor and Test Networks

## What this control checks

PCI DSS Requirement 10.1 requires that audit trails be implemented to link
all access to system components to each individual user. Concord verifies
that AWS CloudTrail is configured with at least one multi-region trail that
is actively logging, so that every API action across the account is captured
and attributable to the identity that performed it. A trail that is missing,
single-region, or stopped leaves control-plane activity uncaptured.

## Why it matters

Without a comprehensive, always-on audit trail there is no reliable way to
reconstruct who did what within the cardholder data environment. A
multi-region CloudTrail trail that is enabled and logging is the account-wide
mechanism that records every management API call and binds it to the calling
principal, which is the foundation for every downstream detection, forensic,
and accountability requirement in PCI DSS Requirement 10. Single-region or
disabled trails create blind spots that an attacker can exploit undetected,
so Concord fails closed when no qualifying trail is present.

## Evidence

Collected from the `aws` source (`audit_trail_status` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no audit-trail evidence collected
- no CloudTrail trail is configured; system components do not produce an audit trail (PCI DSS Requirement 10.1)
- no multi-region CloudTrail trail is both enabled and logging; account activity is not linked to individual users (PCI DSS Requirement 10.1)
- multi-region CloudTrail trail <value> is not currently logging; audit trail is incomplete (PCI DSS Requirement 10.1)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **30m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-10.1-audit-trail-implementation
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss: ["10.1", "10.2", "10.2.1"]
  soc2: ["CC7.2"]
  nist_800_53: ["AU-2", "AU-3", "AU-12"]
  cis_aws: ["3.1"]
```

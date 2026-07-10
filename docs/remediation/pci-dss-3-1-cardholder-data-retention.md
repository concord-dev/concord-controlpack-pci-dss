# Cardholder data retention and disposal are governed by a current, signed policy

`PCI-DSS-3.1-cardholder-data-retention` · framework **pci-dss** · severity **high** · Protect Cardholder Data

## What this control checks

PCI DSS v4.0 Requirement 3.1 (and 3.2.1) requires cardholder data to be
kept to the minimum necessary and disposed of once it is no longer
required for legal, regulatory, or business reasons, governed by a
documented data-retention and disposal policy that is reviewed at a
defined cadence. Concord reads the version-controlled retention policy
from the repository and confirms it declares a retention period, an
approved disposal method, a review cadence, and a recent signed review.

## Why it matters

Cardholder data that outlives its business purpose is pure liability:
it expands the audit scope and the blast radius of any breach without
adding value. A retention policy stored as a spreadsheet or a slide
silently goes stale, so Concord anchors the evidence to a git-versioned
document whose freshness and signature can be verified on every run,
turning "we have a policy" into "the policy is current and approved".

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- PCI DSS 3.1: no cardholder-data retention policy evidence collected
- PCI DSS 3.1: no cardholder-data retention policy document found at the configured repository path
- PCI DSS 3.1: retention policy <value> is missing required field <value>
- PCI DSS 3.1: retention policy <value> was last reviewed more than <value> days ago (last_reviewed_at=<value>)
- PCI DSS 3.1: retention policy <value> signature is not verified (signature_verified=<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-3.1-cardholder-data-retention
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss:
  - "3.1"
  - "3.2.1"
  iso27001:
  - "A.8.10"
  soc2:
  - "C1.2"
```

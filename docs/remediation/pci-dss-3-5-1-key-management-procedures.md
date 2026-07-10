# Key-management procedures cover generation, distribution, storage, rotation, and destruction

`PCI-DSS-3.5.1-key-management-procedures` · framework **pci-dss** · severity **high** · Protect Cardholder Data

## What this control checks

PCI DSS v4.0 Requirement 3.5.1 (aligned with 3.6/3.7) requires
documented and implemented procedures for managing the cryptographic
keys that protect stored account data across their full lifecycle:
secure generation, secure distribution, secure storage, rotation at the
end of the cryptoperiod, and retirement/destruction. Concord reads the
version-controlled key-management procedure document and confirms every
lifecycle stage is described, the document is current, and it is signed.

## Why it matters

Enabling KMS rotation (Requirement 3.6.1) is necessary but not
sufficient: PCI also expects the human procedures around key custody to
be written down and followed, because most real key compromises come
from mishandled generation, distribution, or destruction rather than a
missing rotation flag. Verifying one field per lifecycle stage — and
denying per missing stage — makes a partially documented procedure fail
loudly instead of passing on the strength of the stages that happen to
be filled in.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- PCI DSS 3.5.1: no key-management procedure evidence collected
- PCI DSS 3.5.1: no key-management procedure document found at the configured repository path
- PCI DSS 3.5.1: key-management procedure <value> is missing required field <value>
- PCI DSS 3.5.1: key-management procedure <value> was last reviewed more than <value> days ago (last_reviewed_at=<value>)
- PCI DSS 3.5.1: key-management procedure <value> signature is not verified (signature_verified=<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-3.5.1-key-management-procedures
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss:
  - "3.5.1"
  - "3.6.1"
  nist_800_53:
  - "SC-12"
  iso27001:
  - "A.8.24"
  soc2:
  - "C1.1"
```

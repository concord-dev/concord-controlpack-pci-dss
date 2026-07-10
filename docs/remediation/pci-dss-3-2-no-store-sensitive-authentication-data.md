# Sensitive authentication data is not stored after authorization

`PCI-DSS-3.2-no-store-sensitive-authentication-data` · framework **pci-dss** · severity **critical** · Protect Cardholder Data

## What this control checks

PCI DSS v4.0 Requirement 3.2 (and 3.3.1) prohibits storing sensitive
authentication data — full track data, card verification codes (CAV2,
CVC2, CVV2, CID), and PINs / PIN blocks — after authorization, even when
encrypted. Because no single cloud API reports "SAD is absent
everywhere", Concord verifies a signed engineering attestation that the
prohibition is enforced, the cardholder data flow has been reviewed, and
a scanning tool actively searches for prohibited SAD.

## Why it matters

Stored SAD is the highest-severity failure in PCI Requirement 3: it is
exactly the data that lets an attacker clone a card, and its retention
is one of the leading causes of catastrophic breaches. A pure
point-in-time cloud scan cannot prove a negative across every log,
backup, and datastore, so the defensible evidence is a fresh, signed
attestation backed by continuous scanning — and the control fails closed
unless the prohibition is explicitly attested as enforced.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- PCI DSS 3.2: no sensitive-authentication-data attestation evidence collected
- PCI DSS 3.2: no sensitive-authentication-data attestation document found at the configured repository path
- PCI DSS 3.2: attestation <value> is missing required field <value>
- PCI DSS 3.2: attestation <value> does not affirm sad_storage_prohibited=true (got <value>)
- PCI DSS 3.2: attestation <value> was last reviewed more than <value> days ago (last_reviewed_at=<value>)
- PCI DSS 3.2: attestation <value> signature is not verified (signature_verified=<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-3.2-no-store-sensitive-authentication-data
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss:
  - "3.2"
  - "3.3.1"
  iso27001:
  - "A.8.10"
  soc2:
  - "C1.1"
```

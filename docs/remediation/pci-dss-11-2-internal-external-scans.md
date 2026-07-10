# Internal and external vulnerability scans are run at least quarterly

`PCI-DSS-11.2-internal-external-scans` · framework **pci-dss** · severity **high** · Regularly Monitor and Test Networks

## What this control checks

PCI DSS v4.0 Requirement 11.3.1/11.3.2 (formerly 11.2) requires internal
and external vulnerability scans at least once every three months and
after significant changes, with all high-risk and critical findings
resolved and a passing rescan obtained. The external scan must be
performed by a PCI SSC Approved Scanning Vendor (ASV). Because an ASV scan
is an out-of-band, vendor-attested artifact that no cloud API can fully
reproduce, this control verifies a signed structured attestation of the
quarterly scan cycle: the last internal and external scan dates, the tool
or ASV used, the count of unresolved critical findings, and freshness
within 92 days.

## Why it matters

A purely technical check (for example, "is AWS Inspector enabled?")
cannot satisfy Requirement 11.3.2: AWS Inspector is not an Approved
Scanning Vendor, and the ASV external scan plus its Attestation of Scan
Compliance are the actual audit evidence PCI expects. Continuous cloud
scanning is valuable but complements rather than replaces the quarterly
ASV cadence, so this control is modelled as a structured, signed
attestation. It fails closed: an attestation that is absent, unsigned,
missing a required field, stale beyond 92 days, or reporting unresolved
critical findings all deny.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no vulnerability-scan attestation collected — quarterly internal and external scans cannot be evidenced (PCI DSS 11.3, fail closed)
- scan attestation is missing required field <value> (PCI DSS 11.3)
- vulnerability-scan attestation is not signed by an authorised approver (PCI DSS 11.3)
- scan attestation does not record test_age_days — scan freshness cannot be verified (PCI DSS 11.3, fail closed)
- most recent vulnerability scan cycle is <value> days old — PCI DSS 11.3 requires scans at least every <value> days
- <value> critical vulnerability finding(s) remain unresolved — PCI DSS 11.3 requires remediation and a passing rescan

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-11.2-internal-external-scans
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss:
  - "11.2"
  - "11.3.1"
  - "11.3.2"
  soc2:
  - "CC7.1"
  nist_800_53:
  - "RA-5"
  iso27001:
  - "A.8.8"
```

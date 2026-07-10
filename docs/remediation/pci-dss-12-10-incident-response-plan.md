# An incident response plan is documented, tested, and reviewed at least annually

`PCI-DSS-12.10-incident-response-plan` · framework **pci-dss** · severity **high** · Maintain an Information Security Policy

## What this control checks

PCI DSS Requirement 12.10 requires an incident response plan to be
documented and ready to be activated immediately in the event of a suspected
or confirmed breach of cardholder data, with defined roles, detection and
escalation procedures, and a communication plan, and it must be reviewed and
tested at least once every 12 months. Concord evaluates a signed,
version-controlled attestation of the incident response plan. The
attestation must be current, cosign-verified, name the roles and their
responsibilities, describe detection and escalation, describe the
communication plan, and record when the plan was last tested and reviewed.

## Why it matters

An incident response plan that has never been tested is not a plan, it is a
hope — and a breach is the worst time to discover the escalation path is
wrong or no one owns notification. Requirement 12.10 is explicit that the
plan be exercised at least annually, so Concord enforces both a review
freshness and a test freshness check in addition to the required content.
QSAs test 12.10 by asking for the plan, the roster of responders, and the
date of the last tabletop or live test; failing a plan that is stale or
untested prevents the false assurance of a document that exists on paper
only.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no incident-response-plan attestation found (expected a signed attestation at policies/governance/incident-response-plan.yaml)
- no incident-response-plan attestation document found (expected a signed attestation at policies/governance/incident-response-plan.yaml)
- incident-response-plan attestation is missing required field <value>
- incident-response plan last reviewed <value> days ago — PCI DSS Requirement 12.10 expects review at least every 12 months
- incident-response plan last tested <value> days ago — PCI DSS Requirement 12.10 expects the plan to be tested at least every 12 months
- incident-response-plan attestation cosign signature did not verify

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-12.10-incident-response-plan
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss:
  - "12.10"
  - "12.10.1"
  soc2:
  - "CC7.3"
  - "CC7.4"
  - "CC7.5"
  nist_800_53:
  - "IR-1"
  - "IR-4"
  - "IR-8"
  iso27001:
  - "A.5.24"
  - "A.5.26"
```

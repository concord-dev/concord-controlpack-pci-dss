# A formal, approved change-control process governs network and firewall configuration changes

`PCI-DSS-1.1.1-network-config-change-control` · framework **pci-dss** · severity **high** · Build and Maintain a Secure Network and Systems

## What this control checks

PCI DSS v4.0 Requirement 1.1.1 requires that all security policies and
operational procedures for managing network security controls are
documented, kept current, in use, and known to affected parties, including
a formal process for approving and testing changes to network connections
and to firewall and router configurations. This control reads a signed
change-control procedure from the policy repository and confirms it defines
the approval process, the roles authorized to approve changes, the ticket
referencing convention that links each change to its record, and the date
it was last reviewed. The procedure must have been reviewed within the last
365 days and carry a verified signature.

## Why it matters

Undocumented or unapproved firewall and routing changes are a leading cause
of the misconfigurations that this requirement exists to prevent, and they
are exactly what an assessor probes when validating Requirement 1.1.1.
A credible procedure names who can approve a change, how each change is
ticketed and traceable, and proves it is a living document through recent
review and a valid signature. Checking these specific fields rather than
the mere existence of a file distinguishes a real, auditable control from an
aspirational policy statement.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no network change-control procedure found at policies/network-change-control-procedure.yaml (PCI DSS Requirement 1.1.1)
- no network change-control procedure document found at policies/network-change-control-procedure.yaml (PCI DSS Requirement 1.1.1)
- network change-control procedure is missing required field <value> (PCI DSS Requirement 1.1.1)
- network change-control procedure was last reviewed <value> days ago; Requirement 1.1.1 requires the procedure be kept current (reviewed at least every <value> days)
- network change-control procedure signature did not verify (PCI DSS Requirement 1.1.1)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-1.1.1-network-config-change-control
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss:
  - "1.1.1"
  - "1.2.2"
  nist_800_53:
  - "CM-3"
  - "SA-3"
  soc2:
  - "CC8.1"
  iso27001:
  - "A.8.32"
```

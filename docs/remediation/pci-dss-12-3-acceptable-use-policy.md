# An acceptable use policy for critical technologies is documented and signed

`PCI-DSS-12.3-acceptable-use-policy` · framework **pci-dss** · severity **medium** · Maintain an Information Security Policy

## What this control checks

PCI DSS Requirement 12.3 requires acceptable use policies for critical
technologies — such as remote access, wireless, removable media, laptops,
and messaging — to be defined and enforced, including explicit approval by
authorized parties before those technologies are used. Concord evaluates a
signed, version-controlled attestation of the acceptable use policy. The
attestation must be current, cosign-verified, enumerate the approved
technologies and their usage rules, and confirm that explicit approval is
required before a critical technology is deployed.

## Why it matters

Critical technologies are the ones most often abused to reach cardholder
data — an unapproved remote-access tool or personal USB drive can bypass
the entire control set. Requirement 12.3 forces the organization to decide,
in writing, which technologies are permitted, the rules for using them, and
that a named authority must approve their use. Capturing that as a signed,
annually reviewed artifact gives the assessor a definitive list rather than
tribal knowledge, and the explicit-approval flag makes the approval
requirement machine-checkable.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no acceptable-use-policy attestation found (expected a signed attestation at policies/governance/acceptable-use-policy.yaml)
- no acceptable-use-policy attestation document found (expected a signed attestation at policies/governance/acceptable-use-policy.yaml)
- acceptable-use-policy attestation is missing required field <value>
- acceptable-use-policy attestation must confirm explicit_approval_required = true (authorized approval before use of critical technologies)
- acceptable-use-policy attestation last reviewed <value> days ago — PCI DSS Requirement 12.3 expects review at least every 12 months
- acceptable-use-policy attestation cosign signature did not verify

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-12.3-acceptable-use-policy
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss:
  - "12.3"
  - "12.3.1"
  soc2:
  - "CC1.1"
  - "CC2.2"
  nist_800_53:
  - "PL-4"
  - "AC-20"
  iso27001:
  - "A.5.10"
  - "A.8.1"
```

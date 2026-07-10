# Vendor-supplied defaults are changed before deploying any system component

`PCI-DSS-2.1.1-default-passwords-changed` · framework **pci-dss** · severity **critical** · Build and Maintain a Secure Network

## What this control checks

PCI DSS Requirement 2.1.1 requires that vendor-supplied defaults are
always changed, and unnecessary default accounts are removed or
disabled, before a system component is installed on the network — this
covers default passwords, SNMP community strings, and other default
security parameters. Because defaults span appliances, images, and
managed services with no single cloud signal, Concord verifies a signed
attestation that a baseline hardening process exists and that changing
defaults is verified before deployment.

## Why it matters

Vendor defaults are public knowledge and are among the first things an
attacker tries, so an unchanged default is effectively an open door.
Hardening happens across so many component types — network gear, golden
images, SaaS admin accounts — that a single scanner cannot see all of
it; the durable evidence is a signed attestation of a documented
baseline plus a verification gate in the deployment pipeline, and the
control fails closed unless both are attested and current.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- PCI DSS 2.1.1: no vendor-default hardening attestation evidence collected
- PCI DSS 2.1.1: no vendor-default hardening attestation document found at the configured repository path
- PCI DSS 2.1.1: hardening attestation <value> is missing required field <value>
- PCI DSS 2.1.1: hardening attestation <value> was last reviewed more than <value> days ago (last_reviewed_at=<value>)
- PCI DSS 2.1.1: hardening attestation <value> signature is not verified (signature_verified=<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-2.1.1-default-passwords-changed
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss:
  - "2.1.1"
  - "2.2.2"
  nist_800_53:
  - "CM-6"
  iso27001:
  - "A.8.9"
  soc2:
  - "CC6.1"
```

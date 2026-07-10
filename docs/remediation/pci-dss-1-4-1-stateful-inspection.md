# Network ACLs at the trusted/untrusted boundary enforce an explicit default-deny

`PCI-DSS-1.4.1-stateful-inspection` · framework **pci-dss** · severity **high** · Build and Maintain a Secure Network and Systems

## What this control checks

PCI DSS v4.0 Requirement 1.4.1 requires that network security controls are
implemented between trusted and untrusted networks so that only authorized
connections are permitted. Stateful security groups provide connection
tracking, but the subnet boundary must also fail closed. This control
inspects the network ACLs that guard the boundary and confirms that each
one carries an explicit deny-all catch-all rule for both inbound and
outbound traffic, so any connection not expressly permitted is dropped
rather than relying on implicit behavior. An environment with no network
ACLs, or with an ACL missing the ingress or egress deny-all fallback, is
reported as a violation.

## Why it matters

The recurring theme in Requirement 1.4 is that the boundary between trusted
and untrusted networks must be deliberate and deny by default. Relying on
AWS's implicit deny at rule 32767 leaves the posture invisible and easy to
undermine with a later permissive rule, so assessors look for an explicit
deny-all entry that documents intent and cannot be silently overridden.
Requiring the explicit catch-all on both directions demonstrates that the
NSC governing the boundary fails closed, which is the enforceable and
verifiable core of a stateful, default-deny network boundary.

## Evidence

Collected from the `aws` source (`network_acls` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no network-ACL evidence collected
- no network ACLs found; the boundary between trusted and untrusted networks is not enforced by any NSC (PCI DSS Requirement 1.4.1)
- network ACL <value> has no explicit inbound deny-all rule; NSCs must fail closed and specifically deny all inbound traffic that is not expressly permitted (PCI DSS Requirement 1.4.1)
- network ACL <value> has no explicit outbound deny-all rule; the boundary must fail closed on egress as well as ingress (PCI DSS Requirement 1.4.1)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-1.4.1-stateful-inspection
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss:
  - "1.4.1"
  nist_800_53:
  - "SC-7"
  - "AC-4"
  soc2:
  - "CC6.6"
  iso27001:
  - "A.8.20"
```

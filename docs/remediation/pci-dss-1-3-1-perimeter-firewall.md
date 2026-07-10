# No private or cardholder-data-environment resource is directly reachable from untrusted networks

`PCI-DSS-1.3.1-perimeter-firewall` · framework **pci-dss** · severity **high** · Build and Maintain a Secure Network and Systems

## What this control checks

PCI DSS v4.0 Requirement 1.3.1 requires that inbound traffic to the
cardholder-data environment (CDE) is restricted to only necessary traffic
and that all other traffic is specifically denied. This control inspects
every security group and, for those protecting a private- or CDE-tier
resource, confirms that no ingress rule permits direct access from an
untrusted network (0.0.0.0/0 or ::/0). Any private or CDE security group
with a direct Internet ingress rule is reported as a perimeter violation.

## Why it matters

Direct Internet reachability of a database, application backend, or any
CDE component is one of the highest-signal findings a QSA can identify: it
means the perimeter that is supposed to sit between untrusted networks and
the cardholder data is either missing or misconfigured. By classifying each
security group by the tier it protects and requiring that private and CDE
tiers have zero direct ingress from the Internet, this control enforces the
"specifically deny all other traffic" intent of Requirement 1.3.1 rather
than merely checking a handful of well-known ports.

## Evidence

Collected from the `aws` source (`security_groups` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no security-group evidence collected
- security group <value> protects a <value>-tier resource but permits direct inbound from the untrusted network <value>; the perimeter must specifically deny all direct Internet access to private and CDE resources (PCI DSS Requirement 1.3.1)
- security group <value> does not declare the network tier it protects; every group must be classified so CDE and private tiers can be confirmed isolated from untrusted networks (PCI DSS Requirement 1.3.1)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-1.3.1-perimeter-firewall
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss:
  - "1.3.1"
  - "1.3.2"
  nist_800_53:
  - "SC-7"
  - "SC-7(3)"
  soc2:
  - "CC6.6"
  iso27001:
  - "A.8.22"
```

# Security-group rulesets restrict inbound Internet traffic to an allow-list of necessary services

`PCI-DSS-1.2.1-allow-list-traffic-restriction` · framework **pci-dss** · severity **high** · Build and Maintain a Secure Network and Systems

## What this control checks

PCI DSS v4.0 Requirement 1.2.1 requires that configuration standards for
network security control (NSC) rulesets are defined and implemented so that
only necessary traffic is permitted and all other traffic is denied. This
control inspects every security-group ruleset and confirms that inbound
rules open to the untrusted Internet (0.0.0.0/0) are limited to an explicit
allow-list of necessary public services. Any Internet-facing rule targeting
a port outside the allow-list, spanning a port range, or omitting a port
bound (an "all traffic" rule) is reported as a violation.

## Why it matters

An allow-list posture is the difference between a deliberately maintained
ruleset and a permissive one that accreted over time. Assessors validating
Requirement 1.2.1 expect to see that only justified, documented services are
reachable from untrusted networks and that everything else is denied by
default. Evaluating each rule against a small allow-list of necessary public
ports (HTTP/HTTPS front doors) surfaces the broad "0.0.0.0/0 to any port"
or wide-range rules that most often expose the cardholder-data environment.

## Evidence

Collected from the `aws` source (`security_groups` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no security-group evidence collected
- security group <value> allows all inbound traffic from 0.0.0.0/0 with no port restriction; NSC rulesets must permit only the allow-listed necessary services 80/443 and deny all other traffic (PCI DSS Requirement 1.2.1)
- security group <value> allows 0.0.0.0/0 inbound to ports <value>-<value>, which are not limited to the allow-list of necessary public services 80/443 (PCI DSS Requirement 1.2.1)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-1.2.1-allow-list-traffic-restriction
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss:
  - "1.2.1"
  - "1.2.5"
  nist_800_53:
  - "AC-4"
  - "SC-7"
  soc2:
  - "CC6.6"
  iso27001:
  - "A.8.20"
```

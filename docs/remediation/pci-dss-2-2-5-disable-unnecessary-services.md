# No security group permits unnecessary or insecure legacy services

`PCI-DSS-2.2.5-disable-unnecessary-services` · framework **pci-dss** · severity **high** · Build and Maintain a Secure Network and Systems

## What this control checks

PCI DSS v4.0 Requirement 2.2.5 requires that all unnecessary functionality,
including unnecessary services, protocols, daemons, and ports, is removed or
disabled as part of the system configuration standard. This control inspects
every security-group ruleset and reports any rule that permits a known
unnecessary or insecure legacy service, such as FTP, Telnet, TFTP, the
NetBIOS/SMB family, RPC/portmapper, NFS, rsync, VNC, or X11. A rule that
opens all ports and protocols is also reported, because it necessarily
exposes these services.

## Why it matters

Every enabled service is attack surface, and legacy services such as Telnet,
FTP, and SMB carry credentials or data in the clear and are repeatedly
implicated in cardholder-data breaches. Assessors validating Requirement
2.2.5 expect the configuration standard to explicitly disable functionality
that is not needed; the fastest evidence that it has not been applied is a
firewall rule that still permits one of these services. Enumerating the
unnecessary service ports and failing closed on any "all ports" rule turns
that expectation into a concrete, repeatable check.

## Evidence

Collected from the `aws` source (`security_groups` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no security-group evidence collected
- security group <value> permits <value> (port <value>) from <value>; this unnecessary/insecure service must be removed or disabled per PCI DSS Requirement 2.2.5
- security group <value> permits all ports and protocols inbound from <value>, necessarily exposing unnecessary and insecure services that Requirement 2.2.5 requires to be disabled

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-2.2.5-disable-unnecessary-services
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss:
  - "2.2.5"
  - "2.2.4"
  nist_800_53:
  - "CM-7"
  - "CM-7(1)"
  soc2:
  - "CC6.6"
  iso27001:
  - "A.8.9"
```

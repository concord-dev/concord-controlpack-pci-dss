# Non-console administrative access is restricted to encrypted channels

`PCI-DSS-2.3-encrypt-non-console-admin` · framework **pci-dss** · severity **critical** · Build and Maintain a Secure Network and Systems

## What this control checks

PCI DSS v4.0 Requirement 2.3 requires that all non-console administrative
access is encrypted using strong cryptography. This control inspects every
security-group ruleset and reports any rule that permits a cleartext
remote-administration protocol, such as Telnet, rlogin, rexec, rsh,
unencrypted VNC, or unencrypted X11. It also reports any rule flagged as
administrative that is not confirmed to be encrypted, so that services such
as RDP or web administration exposed without TLS are caught and rules that
omit their encryption status fail closed.

## Why it matters

Administrative sessions carry the highest-value credentials in the
environment; if that traffic crosses the network in the clear, an attacker
who can observe it gains privileged access directly. Assessors validating
Requirement 2.3 look for proof that administrators reach systems only over
SSH, TLS, or an equivalent, and that legacy cleartext management protocols
are not merely discouraged but blocked at the network layer. Failing closed
when a rule does not affirm encryption prevents an unlabeled or misconfigured
administrative path from silently passing.

## Evidence

Collected from the `aws` source (`security_groups` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no security-group evidence collected
- security group <value> permits <value> (port <value>) for administrative access; PCI DSS Requirement 2.3 requires all non-console administrative access to use strong cryptography such as SSH or TLS
- security group <value> exposes an administrative service on ports <value>-<value> that is not confirmed to use encryption; non-console administrative access must use strong cryptography (PCI DSS Requirement 2.3)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-2.3-encrypt-non-console-admin
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss:
  - "2.3"
  nist_800_53:
  - "AC-17(2)"
  - "SC-8"
  soc2:
  - "CC6.7"
  iso27001:
  - "A.8.5"
```

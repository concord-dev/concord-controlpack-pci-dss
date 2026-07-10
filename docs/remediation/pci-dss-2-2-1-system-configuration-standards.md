# Configuration standards exist and are aligned with CIS / vendor benchmarks

`PCI-DSS-2.2.1-system-configuration-standards` · framework **pci-dss** · severity **high** · Apply Secure Configurations to All System Components

## What this control checks

PCI DSS v4.0 Requirement 2.2.1 requires configuration standards to be
developed, implemented, and maintained for all system components, and
that those standards are consistent with industry-accepted hardening
benchmarks (for example CIS or vendor guidance) and cover all known
security vulnerabilities. Concord verifies this technically in AWS: the
AWS Config recorder must be enabled and recording in every active region
so baseline configuration is continuously captured, and at least one
benchmark-aligned Config conformance pack must be deployed and reporting
a COMPLIANT state, proving the standard is not just documented but
enforced against live resources.

## Why it matters

A documented hardening standard provides no assurance unless deviations
from it are continuously detected. Enabling the AWS Config recorder gives
an authoritative, tamper-evident record of every resource configuration,
and mapping a CIS- or PCI-aligned conformance pack onto that record turns
the written standard into automated, evidence-backed detection. If the
recorder is disabled in a region, drift in that region is invisible; if a
conformance pack reports NON_COMPLIANT, live resources have diverged from
the benchmark and must be remediated. Checking both together prevents the
false assurance of a standard that exists only on paper.

## Evidence

Collected from the `aws` source (`config_conformance_status` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no AWS Config evidence collected
- AWS Config recorder is not recording in active region <value>
- no benchmark-aligned Config conformance pack is deployed to enforce configuration standards
- Config conformance pack <value> is <value> (expected COMPLIANT)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-2.2.1-system-configuration-standards
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss: ["2.2.1"]
  soc2: ["CC7.1"]
  nist_800_53: ["CM-2", "CM-6"]
  iso27001: ["A.8.9"]
```

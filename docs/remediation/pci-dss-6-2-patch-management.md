# Critical security patches are applied within 30 days

`PCI-DSS-6.2-patch-management` · framework **pci-dss** · severity **critical** · Develop and Maintain Secure Systems and Software

## What this control checks

PCI DSS Requirement 6.2 requires that all system components and software
are protected from known vulnerabilities by installing applicable
vendor-supplied security patches, with critical and high-severity patches
installed within one month of release (under PCI DSS v4.0 this expectation
is carried in Requirement 6.3.3). Concord verifies this technically by
reading AWS Systems Manager (SSM) Patch Manager compliance: every managed
instance in scope must report a COMPLIANT patch state, and no instance may
have a missing critical or security patch older than 30 days.

## Why it matters

Unpatched, publicly known vulnerabilities are among the most common root
causes of cardholder-data breaches, because working exploits are widely
available soon after disclosure. Enforcing a 30-day ceiling on missing
critical and security patches, measured directly from SSM Patch Manager
rather than a self-attested spreadsheet, closes the window in which an
attacker can weaponize a known flaw. Evaluating each instance individually
means a single unpatched host in the cardholder-data environment fails the
control rather than being averaged away by a healthy fleet, and the
fail-closed default treats an instance with no reported patch state as
non-compliant.

## Evidence

Collected from the `aws` source (`ssm_patch_compliance` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no SSM patch-compliance evidence collected
- instance <value> reports patch-compliance status <value> (expected COMPLIANT)
- instance <value> has a missing critical/security patch <value> days old (SLA <value> days)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **3h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-6.2-patch-management
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss: ["6.2", "6.3.3"]
  soc2: ["CC7.1"]
  nist_800_53: ["SI-2", "RA-5"]
  iso27001: ["A.8.8"]
```

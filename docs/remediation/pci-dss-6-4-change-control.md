# Change control processes are documented for system component changes

`PCI-DSS-6.4-change-control` · framework **pci-dss** · severity **medium** · Develop and Maintain Secure Systems and Software

## What this control checks

PCI DSS Requirement 6.4 requires that changes to all system components in
the cardholder-data environment follow documented change-control
procedures (under PCI DSS v4.0 this is Requirement 6.5.1). Concord reads a
cosigned attestation of the change-control process, held under version
control in GitHub, and verifies it documents a change-approval process,
enforces separation of duties between the change requester and the
approver, defines a rollback/backout procedure, and states the testing
required before a change is promoted to production. The attestation must be
signed and reviewed at least once every 12 months.

## Why it matters

Uncontrolled changes are a leading cause of both outages and inadvertent
weakening of security controls, and PCI DSS treats change control as a
core defense for the cardholder-data environment. Requiring a documented
approval workflow with enforced separation of duties prevents any single
person from unilaterally pushing an unreviewed change to production, while
a defined rollback procedure and mandatory pre-production testing ensure a
faulty or malicious change can be detected and reversed before it exposes
cardholder data. Requiring a verified signature and annual review keeps an
accountable owner responsible for maintaining the process.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no change-control attestation collected
- no change-control attestation document found at the configured repository path
- change-control attestation missing required field: <value>
- change-control attestation does not confirm separation of duties between change requester and approver
- change-control attestation signature did not verify
- change-control process last reviewed <value>, exceeding the <value>-day review interval

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **3h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-6.4-change-control
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss: ["6.4", "6.5.1"]
  soc2: ["CC8.1"]
  nist_800_53: ["CM-3"]
  iso27001: ["A.8.32"]
```

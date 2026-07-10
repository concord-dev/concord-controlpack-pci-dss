# Web-application firewall protects every public-facing web application

`PCI-DSS-6.6-web-application-firewall` · framework **pci-dss** · severity **high** · Develop and Maintain Secure Systems and Software

## What this control checks

PCI DSS Requirement 6.6 requires public-facing web applications to be
protected against known attacks by an automated technical solution that
continually detects and prevents web-based attacks, such as a web-
application firewall (under PCI DSS v4.0 this is Requirement 6.4.1/6.4.2).
Concord verifies this technically by inventorying every public-facing web
entry point in AWS (internet-facing Application Load Balancers and enabled
CloudFront distributions) and confirming each one has an AWS WAF WebACL
associated. Internal, non-public resources are out of scope and are not
required to carry a WebACL.

## Why it matters

Public-facing web applications are directly reachable by attackers and are
the primary target for injection, cross-site scripting, and other OWASP
Top 10 attacks against cardholder data. A WebACL provides the continuous,
automated inspection Requirement 6.6 demands, so an internet-facing load
balancer or CDN distribution with no WebACL is an unprotected entry point
into the environment. Concord evaluates each public endpoint individually
and fails closed: a resource is flagged unless it explicitly reports an
associated WebACL, so a missing or unreported association is treated as
unprotected rather than assumed safe.

## Evidence

Collected from the `aws` source (`waf_coverage` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no WAF-coverage evidence collected
- public-facing <value> <value> has no associated WAF WebACL

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **3h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-6.6-web-application-firewall
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss: ["6.6", "6.4.1", "6.4.2"]
  soc2: ["CC6.6"]
  nist_800_53: ["SC-7", "SI-4"]
  iso27001: ["A.8.20", "A.8.26"]
```

# PAN is never sent unprotected via end-user messaging technologies

`PCI-DSS-4.2-no-end-user-messaging` · framework **pci-dss** · severity **high** · Protect Cardholder Data

## What this control checks

PCI DSS v4.0 Requirement 4.2.2 requires that the primary account number
(PAN) is never sent, and a policy prohibits sending it, via end-user
messaging technologies such as email, SMS, and chat unless it is
rendered unreadable with strong cryptography. Concord verifies a signed
policy attestation that PAN messaging is prohibited, that the prohibition
covers email, SMS, and chat, and that DLP tooling enforces it.

## Why it matters

End-user messaging is a classic PAN-leakage path: a support agent
pastes a full card number into a chat thread or replies to a customer
email, and the data lands in systems that were never scoped for PCI.
The defensible control combines a written prohibition with DLP
enforcement across every messaging channel, and the policy fails closed
unless the prohibition is explicitly attested and each of the named
channels is in scope.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- PCI DSS 4.2.2: no PAN end-user-messaging policy evidence collected
- PCI DSS 4.2.2: no PAN end-user-messaging policy document found at the configured repository path
- PCI DSS 4.2.2: policy <value> is missing required field <value>
- PCI DSS 4.2.2: policy <value> does not affirm policy_prohibits_pan_messaging=true (got <value>)
- PCI DSS 4.2.2: policy <value> does not cover the <value> messaging channel
- PCI DSS 4.2.2: policy <value> was last reviewed more than <value> days ago (last_reviewed_at=<value>)
- PCI DSS 4.2.2: policy <value> signature is not verified (signature_verified=<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework pci-dss --control-id PCI-DSS-4.2-no-end-user-messaging
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  pci_dss:
  - "4.2"
  - "4.2.2"
  nist_800_53:
  - "SC-8"
  iso27001:
  - "A.8.24"
  soc2:
  - "C1.1"
```

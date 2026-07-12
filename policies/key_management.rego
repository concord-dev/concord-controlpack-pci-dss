package concord.pci_dss.key_management

import rego.v1

# PCI DSS v4.0 §3.5/§3.6 — KMS key rotation for cardholder-data keys.
# Adapted from: Prowler `kms_cmk_rotation_enabled`, Powerpipe AWS PCI v3.2.1
# benchmark `pci_v321_kms_2`.

deny contains msg if {
    not input.aws_kms
    msg := "no KMS evidence collected"
}

deny contains msg if {
    some k in input.aws_kms.keys
    is_pci(k)
    k.key_state == "Enabled"
    not k.rotation_enabled
    msg := sprintf("PCI key %q has rotation disabled", [k.key_id])
}

deny contains msg if {
    some k in input.aws_kms.keys
    is_pci(k)
    k.rotation_enabled
    k.rotation_period_days > 365
    msg := sprintf("PCI key %q rotates every %d days (>365)", [k.key_id, k.rotation_period_days])
}

warn contains msg if {
    some k in input.aws_kms.keys
    is_pci(k)
    k.key_state == "PendingDeletion"
    msg := sprintf("PCI key %q is pending deletion — confirm cardholder data is not still encrypted with it", [k.key_id])
}

# doc 31 §4 — no fail-open tag gates: a resource with no 'pci' tag is neither confirmed in-scope
# nor out-of-scope, so every deny above skips it and it would pass silently.
# Warn on the unclassified resource instead of ignoring it.

warn contains msg if {
    some resource in input.aws_kms.keys
    not classified(resource)
    msg := sprintf("KMS key %q has no pci tag, so this control's checks did not apply to it — tag pci=true to bring it into cardholder-data (PCI) scope or pci=false to confirm it is out of scope", [resource.key_id])
}

is_pci(k) if {
    k.tags.pci == "true"
}

classified(resource) if resource.tags.pci == "true"

classified(resource) if resource.tags.pci == "false"

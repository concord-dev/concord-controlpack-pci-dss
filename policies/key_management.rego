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

is_pci(k) if {
    k.tags.pci == "true"
}

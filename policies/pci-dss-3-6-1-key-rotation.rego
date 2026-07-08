package concord.pci_dss.r_3_6_1

import rego.v1

# PCI DSS v4.0 Requirement 3.6.1 / 3.7.4 — cryptographic keys protecting
# stored account data must rotate at least annually. Scoped to AWS KMS keys
# tagged pci=true, matching the tagging convention used by 3.4 (render PAN
# unreadable) and 3.5 (key management) in this pack.
#
# Adapted from: Prowler `kms_cmk_rotation_enabled`, Powerpipe AWS PCI v3.2.1
# benchmark `pci_v321_kms_2`.

max_rotation_age_days := 365

nanos_per_day := 86400000000000

deny contains msg if {
	not input.aws_kms
	msg := "PCI DSS 3.6.1: no KMS key evidence collected"
}

# Automatic rotation must be explicitly enabled on every enabled PCI key.
deny contains msg if {
	some k in input.aws_kms.keys
	is_pci(k)
	k.key_state == "Enabled"
	not k.rotation_enabled == true
	msg := sprintf("PCI DSS 3.6.1: key %q does not have automatic rotation enabled", [k.key_id])
}

# The configured rotation cadence must not exceed one year.
deny contains msg if {
	some k in input.aws_kms.keys
	is_pci(k)
	k.key_state == "Enabled"
	k.rotation_enabled == true
	k.rotation_period_days > max_rotation_age_days
	msg := sprintf("PCI DSS 3.6.1: key %q rotates every %d days, exceeding the %d-day maximum", [k.key_id, k.rotation_period_days, max_rotation_age_days])
}

# Fail-closed: even with rotation enabled, the key must have *actually* been
# rotated within the window. A missing or stale last_rotated_at is a deny.
deny contains msg if {
	some k in input.aws_kms.keys
	is_pci(k)
	k.key_state == "Enabled"
	k.rotation_enabled == true
	not rotated_within_window(k)
	msg := sprintf("PCI DSS 3.6.1: key %q has not been rotated within the last %d days (last_rotated_at=%v)", [k.key_id, max_rotation_age_days, object.get(k, "last_rotated_at", "unknown")])
}

# Surface keys pending deletion so operators confirm no cardholder data is
# still encrypted under them, but do not fail the control on that alone.
warn contains msg if {
	some k in input.aws_kms.keys
	is_pci(k)
	k.key_state == "PendingDeletion"
	msg := sprintf("PCI DSS 3.6.1: key %q is pending deletion — confirm no stored account data still depends on it", [k.key_id])
}

rotated_within_window(k) if {
	k.last_rotated_at
	rotated_ns := time.parse_rfc3339_ns(k.last_rotated_at)
	cutoff_ns := time.now_ns() - (max_rotation_age_days * nanos_per_day)
	rotated_ns >= cutoff_ns
}

is_pci(k) if {
	k.tags.pci == "true"
}

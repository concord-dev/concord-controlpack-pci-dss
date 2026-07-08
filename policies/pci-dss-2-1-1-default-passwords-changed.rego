package concord.pci_dss.r_2_1_1

import rego.v1

# PCI DSS Requirement 2.1.1 / 2.2.2 — vendor-supplied defaults must be changed
# and unnecessary default accounts removed before a system component is
# deployed. Evidenced by a signed hardening attestation collected from the
# repository via github/file_glob (frontmatter), so each matched file is in
# input.hardening_attestation.docs with its frontmatter keys plus a "path".

max_review_age_days := 365

nanos_per_day := 86400000000000

required_fields := ["baseline_hardening_process", "defaults_change_verification", "last_reviewed_at", "signature_verified"]

deny contains msg if {
	not input.hardening_attestation
	msg := "PCI DSS 2.1.1: no vendor-default hardening attestation evidence collected"
}

deny contains msg if {
	input.hardening_attestation
	count(object.get(input.hardening_attestation, "docs", [])) == 0
	msg := "PCI DSS 2.1.1: no vendor-default hardening attestation document found at the configured repository path"
}

deny contains msg if {
	some doc in input.hardening_attestation.docs
	some field in required_fields
	not has_value(doc, field)
	msg := sprintf("PCI DSS 2.1.1: hardening attestation %q is missing required field %q", [doc.path, field])
}

# Freshness: the attestation must have been reviewed within the last year.
deny contains msg if {
	some doc in input.hardening_attestation.docs
	has_value(doc, "last_reviewed_at")
	reviewed_ns := time.parse_rfc3339_ns(doc.last_reviewed_at)
	cutoff_ns := time.now_ns() - (max_review_age_days * nanos_per_day)
	reviewed_ns < cutoff_ns
	msg := sprintf("PCI DSS 2.1.1: hardening attestation %q was last reviewed more than %d days ago (last_reviewed_at=%s)", [doc.path, max_review_age_days, doc.last_reviewed_at])
}

# Signature must be an explicit boolean true.
deny contains msg if {
	some doc in input.hardening_attestation.docs
	has_value(doc, "signature_verified")
	not doc.signature_verified == true
	msg := sprintf("PCI DSS 2.1.1: hardening attestation %q signature is not verified (signature_verified=%v)", [doc.path, doc.signature_verified])
}

has_value(doc, key) if {
	v := doc[key]
	not is_blank(v)
}

is_blank(v) if v == null

is_blank(v) if v == ""

is_blank(v) if {
	is_array(v)
	count(v) == 0
}

is_blank(v) if {
	is_object(v)
	count(v) == 0
}

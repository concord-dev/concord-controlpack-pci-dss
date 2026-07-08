package concord.pci_dss.r_3_5_1

import rego.v1

# PCI DSS v4.0 Requirement 3.5.1 — documented key-management procedures must
# cover every lifecycle stage of the keys protecting stored account data.
# The procedure document is collected from the repository via
# github/file_glob (frontmatter), so each matched file is in
# input.key_mgmt_procedures.docs with its frontmatter keys plus a "path".

max_review_age_days := 365

nanos_per_day := 86400000000000

# One required field per key lifecycle stage, plus review freshness and signature.
lifecycle_fields := ["key_generation", "key_distribution", "key_storage", "key_rotation", "key_destruction"]

required_fields := array.concat(lifecycle_fields, ["last_reviewed_at", "signature_verified"])

deny contains msg if {
	not input.key_mgmt_procedures
	msg := "PCI DSS 3.5.1: no key-management procedure evidence collected"
}

deny contains msg if {
	input.key_mgmt_procedures
	count(object.get(input.key_mgmt_procedures, "docs", [])) == 0
	msg := "PCI DSS 3.5.1: no key-management procedure document found at the configured repository path"
}

# Deny per missing lifecycle stage (and per missing review/signature field).
deny contains msg if {
	some doc in input.key_mgmt_procedures.docs
	some field in required_fields
	not has_value(doc, field)
	msg := sprintf("PCI DSS 3.5.1: key-management procedure %q is missing required field %q", [doc.path, field])
}

# Freshness: procedures must have been reviewed within the last year.
deny contains msg if {
	some doc in input.key_mgmt_procedures.docs
	has_value(doc, "last_reviewed_at")
	reviewed_ns := time.parse_rfc3339_ns(doc.last_reviewed_at)
	cutoff_ns := time.now_ns() - (max_review_age_days * nanos_per_day)
	reviewed_ns < cutoff_ns
	msg := sprintf("PCI DSS 3.5.1: key-management procedure %q was last reviewed more than %d days ago (last_reviewed_at=%s)", [doc.path, max_review_age_days, doc.last_reviewed_at])
}

# Signature must be an explicit boolean true.
deny contains msg if {
	some doc in input.key_mgmt_procedures.docs
	has_value(doc, "signature_verified")
	not doc.signature_verified == true
	msg := sprintf("PCI DSS 3.5.1: key-management procedure %q signature is not verified (signature_verified=%v)", [doc.path, doc.signature_verified])
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

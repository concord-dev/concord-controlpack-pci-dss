package concord.pci_dss.r_3_1

import rego.v1

# PCI DSS v4.0 Requirement 3.1 / 3.2.1 — cardholder data retention and
# disposal is governed by a documented, current, signed policy. The policy
# document is collected from the repository via github/file_glob with
# frontmatter parsing, so each matched file appears in input.retention_policy.docs
# with its frontmatter keys plus a "path".

max_review_age_days := 365

nanos_per_day := 86400000000000

required_fields := ["retention_period", "disposal_method", "review_cadence", "last_reviewed_at", "signature_verified"]

deny contains msg if {
	not input.retention_policy
	msg := "PCI DSS 3.1: no cardholder-data retention policy evidence collected"
}

deny contains msg if {
	input.retention_policy
	count(object.get(input.retention_policy, "docs", [])) == 0
	msg := "PCI DSS 3.1: no cardholder-data retention policy document found at the configured repository path"
}

# Every required field must be present and non-empty (absent, empty string,
# and empty collection all count as missing).
deny contains msg if {
	some doc in input.retention_policy.docs
	some field in required_fields
	not has_value(doc, field)
	msg := sprintf("PCI DSS 3.1: retention policy %q is missing required field %q", [doc.path, field])
}

# Freshness: the policy must have been reviewed within the last year.
deny contains msg if {
	some doc in input.retention_policy.docs
	has_value(doc, "last_reviewed_at")
	reviewed_ns := time.parse_rfc3339_ns(doc.last_reviewed_at)
	cutoff_ns := time.now_ns() - (max_review_age_days * nanos_per_day)
	reviewed_ns < cutoff_ns
	msg := sprintf("PCI DSS 3.1: retention policy %q was last reviewed more than %d days ago (last_reviewed_at=%s)", [doc.path, max_review_age_days, doc.last_reviewed_at])
}

# Signature must be an explicit boolean true. Present-but-not-true (e.g. false
# or the string "true") is a distinct, reported failure from an absent field.
deny contains msg if {
	some doc in input.retention_policy.docs
	has_value(doc, "signature_verified")
	not doc.signature_verified == true
	msg := sprintf("PCI DSS 3.1: retention policy %q signature is not verified (signature_verified=%v)", [doc.path, doc.signature_verified])
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

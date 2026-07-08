package concord.pci_dss.r_3_2

import rego.v1

# PCI DSS v4.0 Requirement 3.2 / 3.3.1 — sensitive authentication data (full
# track data, card verification codes, PINs) must not be stored after
# authorization. Evidenced by a signed engineering attestation collected from
# the repository via github/file_glob (frontmatter), so each matched file is
# in input.sad_policy.docs with its frontmatter keys plus a "path".

max_review_age_days := 365

nanos_per_day := 86400000000000

required_fields := ["sad_storage_prohibited", "data_flow_reviewed_at", "scanning_tool", "last_reviewed_at", "signature_verified"]

deny contains msg if {
	not input.sad_policy
	msg := "PCI DSS 3.2: no sensitive-authentication-data attestation evidence collected"
}

deny contains msg if {
	input.sad_policy
	count(object.get(input.sad_policy, "docs", [])) == 0
	msg := "PCI DSS 3.2: no sensitive-authentication-data attestation document found at the configured repository path"
}

deny contains msg if {
	some doc in input.sad_policy.docs
	some field in required_fields
	not has_value(doc, field)
	msg := sprintf("PCI DSS 3.2: attestation %q is missing required field %q", [doc.path, field])
}

# The prohibition must be attested as an explicit boolean true.
deny contains msg if {
	some doc in input.sad_policy.docs
	has_value(doc, "sad_storage_prohibited")
	not doc.sad_storage_prohibited == true
	msg := sprintf("PCI DSS 3.2: attestation %q does not affirm sad_storage_prohibited=true (got %v)", [doc.path, doc.sad_storage_prohibited])
}

# Freshness: the attestation must have been reviewed within the last year.
deny contains msg if {
	some doc in input.sad_policy.docs
	has_value(doc, "last_reviewed_at")
	reviewed_ns := time.parse_rfc3339_ns(doc.last_reviewed_at)
	cutoff_ns := time.now_ns() - (max_review_age_days * nanos_per_day)
	reviewed_ns < cutoff_ns
	msg := sprintf("PCI DSS 3.2: attestation %q was last reviewed more than %d days ago (last_reviewed_at=%s)", [doc.path, max_review_age_days, doc.last_reviewed_at])
}

# Signature must be an explicit boolean true.
deny contains msg if {
	some doc in input.sad_policy.docs
	has_value(doc, "signature_verified")
	not doc.signature_verified == true
	msg := sprintf("PCI DSS 3.2: attestation %q signature is not verified (signature_verified=%v)", [doc.path, doc.signature_verified])
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

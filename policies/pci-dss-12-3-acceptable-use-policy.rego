package concord.pci_dss.r_12_3

import rego.v1

# PCI DSS Requirement 12.3 — acceptable use policy for critical technologies,
# including explicit approval by authorized parties. Concord evaluates a
# signed, version-controlled attestation of the policy. The attestation must be
# current (reviewed within the last 12 months), cosign-verified, enumerate the
# approved technologies and their usage rules, and require explicit approval.
# The attestation is collected via github/file_glob, so each matched file
# appears in input.acceptable_use_attestation.docs with its fields plus a
# "path".

max_review_age_days := 365

required_fields := {
	"approved_technologies",
	"usage_rules",
	"last_reviewed_at",
}

deny contains msg if {
	not input.acceptable_use_attestation
	msg := "no acceptable-use-policy attestation found (expected a signed attestation at policies/governance/acceptable-use-policy.yaml)"
}

deny contains msg if {
	input.acceptable_use_attestation
	count(object.get(input.acceptable_use_attestation, "docs", [])) == 0
	msg := "no acceptable-use-policy attestation document found (expected a signed attestation at policies/governance/acceptable-use-policy.yaml)"
}

deny contains msg if {
	some doc in input.acceptable_use_attestation.docs
	some field in required_fields
	unset(doc, field)
	msg := sprintf("acceptable-use-policy attestation is missing required field %q", [field])
}

# explicit_approval_required is a boolean assertion; an absent or false value
# means critical technologies can be used without authorized approval, which
# fails Requirement 12.3.1.
deny contains msg if {
	some doc in input.acceptable_use_attestation.docs
	not doc.explicit_approval_required
	msg := "acceptable-use-policy attestation must confirm explicit_approval_required = true (authorized approval before use of critical technologies)"
}

deny contains msg if {
	some doc in input.acceptable_use_attestation.docs
	doc.review_age_days > max_review_age_days
	msg := sprintf("acceptable-use-policy attestation last reviewed %d days ago — PCI DSS Requirement 12.3 expects review at least every 12 months", [doc.review_age_days])
}

deny contains msg if {
	some doc in input.acceptable_use_attestation.docs
	not doc.signature_verified
	msg := "acceptable-use-policy attestation cosign signature did not verify"
}

# unset treats an absent key, an empty string, and an empty array all as
# "not provided" so a stub attestation cannot silently satisfy a required field.
unset(obj, field) if not obj[field]

unset(obj, field) if obj[field] == ""

unset(obj, field) if {
	is_array(obj[field])
	count(obj[field]) == 0
}

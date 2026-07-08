package concord.pci_dss.r_9_2

import rego.v1

# PCI DSS Requirement 9.2 — visitor identification, escort, and logging in the
# cardholder data environment. Reception and badge/visitor logs are not
# reachable as cloud telemetry, so Concord evaluates a signed,
# version-controlled attestation of the visitor-management program. The
# attestation must be current (reviewed within the last 12 months),
# cosign-verified, and populated with the required program elements. The
# attestation is collected via github/file_glob, so each matched file appears
# in input.visitor_attestation.docs with its fields plus a "path".

max_review_age_days := 365

required_fields := {
	"visitor_identification_process",
	"escort_policy",
	"visitor_log_retention",
	"last_reviewed_at",
}

deny contains msg if {
	not input.visitor_attestation
	msg := "no visitor-identification attestation found (expected a signed attestation at policies/physical/visitor-management.yaml)"
}

deny contains msg if {
	input.visitor_attestation
	count(object.get(input.visitor_attestation, "docs", [])) == 0
	msg := "no visitor-identification attestation document found (expected a signed attestation at policies/physical/visitor-management.yaml)"
}

deny contains msg if {
	some doc in input.visitor_attestation.docs
	some field in required_fields
	unset(doc, field)
	msg := sprintf("visitor-identification attestation is missing required field %q", [field])
}

deny contains msg if {
	some doc in input.visitor_attestation.docs
	doc.review_age_days > max_review_age_days
	msg := sprintf("visitor-identification attestation last reviewed %d days ago — PCI DSS Requirement 9.2 expects review at least every 12 months", [doc.review_age_days])
}

deny contains msg if {
	some doc in input.visitor_attestation.docs
	not doc.signature_verified
	msg := "visitor-identification attestation cosign signature did not verify"
}

# unset treats an absent key, an empty string, and an empty array all as
# "not provided" so a stub attestation cannot silently satisfy a required field.
unset(obj, field) if not obj[field]

unset(obj, field) if obj[field] == ""

unset(obj, field) if {
	is_array(obj[field])
	count(obj[field]) == 0
}

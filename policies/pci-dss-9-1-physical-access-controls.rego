package concord.pci_dss.r_9_1

import rego.v1

# PCI DSS Requirement 9.1 — Restrict Physical Access to Cardholder Data.
# No cloud API reports who badged into a data center or wiring closet, so
# Concord evaluates a signed, version-controlled attestation of the physical
# access program. The attestation must be current (reviewed within the last 12
# months), cosign-verified, and populated with the required program elements.
# The attestation is collected via github/file_glob, so each matched file
# appears in input.physical_access_attestation.docs with its fields plus a
# "path".

max_review_age_days := 365

required_fields := {
	"access_control_measures",
	"authorized_roles",
	"access_log_retention",
	"last_reviewed_at",
}

deny contains msg if {
	not input.physical_access_attestation
	msg := "no physical-access-controls attestation found (expected a signed attestation at policies/physical/physical-access-controls.yaml)"
}

deny contains msg if {
	input.physical_access_attestation
	count(object.get(input.physical_access_attestation, "docs", [])) == 0
	msg := "no physical-access-controls attestation document found (expected a signed attestation at policies/physical/physical-access-controls.yaml)"
}

deny contains msg if {
	some doc in input.physical_access_attestation.docs
	some field in required_fields
	unset(doc, field)
	msg := sprintf("physical-access-controls attestation is missing required field %q", [field])
}

deny contains msg if {
	some doc in input.physical_access_attestation.docs
	doc.review_age_days > max_review_age_days
	msg := sprintf("physical-access-controls attestation last reviewed %d days ago — PCI DSS Requirement 9.1 expects review at least every 12 months", [doc.review_age_days])
}

deny contains msg if {
	some doc in input.physical_access_attestation.docs
	not doc.signature_verified
	msg := "physical-access-controls attestation cosign signature did not verify"
}

# unset treats an absent key, an empty string, and an empty array all as
# "not provided" so a stub attestation cannot silently satisfy a required field.
unset(obj, field) if not obj[field]

unset(obj, field) if obj[field] == ""

unset(obj, field) if {
	is_array(obj[field])
	count(obj[field]) == 0
}

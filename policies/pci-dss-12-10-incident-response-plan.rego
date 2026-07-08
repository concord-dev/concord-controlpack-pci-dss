package concord.pci_dss.r_12_10

import rego.v1

# PCI DSS Requirement 12.10 — a documented incident response plan that is
# reviewed and tested at least annually. Concord evaluates a signed,
# version-controlled attestation of the plan. The attestation must be current
# (reviewed within the last 12 months), tested within the last 12 months,
# cosign-verified, and populated with the required program elements. The
# attestation is collected via github/file_glob, so each matched file appears
# in input.incident_response_attestation.docs with its fields plus a "path".

max_review_age_days := 365

max_test_age_days := 365

required_fields := {
	"roles_responsibilities",
	"detection_escalation",
	"communication_plan",
	"last_tested_at",
	"last_reviewed_at",
}

deny contains msg if {
	not input.incident_response_attestation
	msg := "no incident-response-plan attestation found (expected a signed attestation at policies/governance/incident-response-plan.yaml)"
}

deny contains msg if {
	input.incident_response_attestation
	count(object.get(input.incident_response_attestation, "docs", [])) == 0
	msg := "no incident-response-plan attestation document found (expected a signed attestation at policies/governance/incident-response-plan.yaml)"
}

deny contains msg if {
	some doc in input.incident_response_attestation.docs
	some field in required_fields
	unset(doc, field)
	msg := sprintf("incident-response-plan attestation is missing required field %q", [field])
}

deny contains msg if {
	some doc in input.incident_response_attestation.docs
	doc.review_age_days > max_review_age_days
	msg := sprintf("incident-response plan last reviewed %d days ago — PCI DSS Requirement 12.10 expects review at least every 12 months", [doc.review_age_days])
}

deny contains msg if {
	some doc in input.incident_response_attestation.docs
	doc.test_age_days > max_test_age_days
	msg := sprintf("incident-response plan last tested %d days ago — PCI DSS Requirement 12.10 expects the plan to be tested at least every 12 months", [doc.test_age_days])
}

deny contains msg if {
	some doc in input.incident_response_attestation.docs
	not doc.signature_verified
	msg := "incident-response-plan attestation cosign signature did not verify"
}

# unset treats an absent key, an empty string, and an empty array all as
# "not provided" so a stub attestation cannot silently satisfy a required field.
unset(obj, field) if not obj[field]

unset(obj, field) if obj[field] == ""

unset(obj, field) if {
	is_array(obj[field])
	count(obj[field]) == 0
}

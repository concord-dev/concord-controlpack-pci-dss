package concord.pci_dss.r_12_2

import rego.v1

# PCI DSS Requirement 12.2 — a documented risk-assessment process that is
# performed at least annually and on significant change. Concord evaluates a
# signed, version-controlled attestation of the program. The attestation must
# be current (assessed within the last 12 months), cosign-verified, populated
# with the required program elements, and confirm that findings are tracked.
# The attestation is collected via github/file_glob, so each matched file
# appears in input.risk_assessment_attestation.docs with its fields plus a
# "path".

max_assessment_age_days := 365

required_fields := {
	"methodology",
	"scope",
	"last_assessment_at",
}

deny contains msg if {
	not input.risk_assessment_attestation
	msg := "no risk-assessment-process attestation found (expected a signed attestation at policies/governance/risk-assessment-process.yaml)"
}

deny contains msg if {
	input.risk_assessment_attestation
	count(object.get(input.risk_assessment_attestation, "docs", [])) == 0
	msg := "no risk-assessment-process attestation document found (expected a signed attestation at policies/governance/risk-assessment-process.yaml)"
}

deny contains msg if {
	some doc in input.risk_assessment_attestation.docs
	some field in required_fields
	unset(doc, field)
	msg := sprintf("risk-assessment-process attestation is missing required field %q", [field])
}

# findings_tracked is a boolean assertion; an absent or false value means the
# process does not drive identified risks to remediation, which fails 12.2.
deny contains msg if {
	some doc in input.risk_assessment_attestation.docs
	not doc.findings_tracked
	msg := "risk-assessment-process attestation must confirm findings_tracked = true (identified risks driven to remediation)"
}

deny contains msg if {
	some doc in input.risk_assessment_attestation.docs
	doc.assessment_age_days > max_assessment_age_days
	msg := sprintf("risk assessment last performed %d days ago — PCI DSS Requirement 12.2 expects an assessment at least every 12 months", [doc.assessment_age_days])
}

deny contains msg if {
	some doc in input.risk_assessment_attestation.docs
	not doc.signature_verified
	msg := "risk-assessment-process attestation cosign signature did not verify"
}

# unset treats an absent key, an empty string, and an empty array all as
# "not provided" so a stub attestation cannot silently satisfy a required field.
unset(obj, field) if not obj[field]

unset(obj, field) if obj[field] == ""

unset(obj, field) if {
	is_array(obj[field])
	count(obj[field]) == 0
}

package concord.pci_dss.pci_dss_6_4_change_control

import rego.v1

# PCI DSS Requirement 6.4 / v4.0 6.5.1 — documented change-control process for
# system-component changes. The signed attestation must document an approval
# process, a rollback procedure, a testing requirement, be reviewed within the
# last 12 months, and explicitly confirm separation of duties between change
# requester and approver. The attestation is collected via github/file_glob,
# so each matched file appears in input.change_control_process.docs with its
# signature_verified flag and its attested_fields object, plus a "path".

max_review_age_days := 365

required_fields := {
	"change_approval_process",
	"rollback_procedure",
	"testing_requirement",
	"last_reviewed_at",
}

deny contains msg if {
	not input.change_control_process
	msg := "no change-control attestation collected"
}

deny contains msg if {
	input.change_control_process
	count(object.get(input.change_control_process, "docs", [])) == 0
	msg := "no change-control attestation document found at the configured repository path"
}

deny contains msg if {
	some doc in input.change_control_process.docs
	some field in required_fields
	field_missing(doc, field)
	msg := sprintf("change-control attestation missing required field: %s", [field])
}

deny contains msg if {
	some doc in input.change_control_process.docs
	not doc.attested_fields.separation_of_duties == true
	msg := "change-control attestation does not confirm separation of duties between change requester and approver"
}

deny contains msg if {
	some doc in input.change_control_process.docs
	not doc.signature_verified == true
	msg := "change-control attestation signature did not verify"
}

deny contains msg if {
	some doc in input.change_control_process.docs
	reviewed_ns := time.parse_rfc3339_ns(doc.attested_fields.last_reviewed_at)
	age_ns := time.now_ns() - reviewed_ns
	age_ns > ((max_review_age_days * 24) * 3600) * 1000000000
	msg := sprintf("change-control process last reviewed %s, exceeding the %d-day review interval", [doc.attested_fields.last_reviewed_at, max_review_age_days])
}

# A required field is missing when it is absent, or present but empty.
field_missing(doc, field) if not doc.attested_fields[field]

field_missing(doc, field) if doc.attested_fields[field] == ""

field_missing(doc, field) if doc.attested_fields[field] == []

field_missing(doc, field) if doc.attested_fields[field] == {}

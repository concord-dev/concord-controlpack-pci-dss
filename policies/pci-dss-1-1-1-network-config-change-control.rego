package concord.pci_dss.r_1_1_1

import rego.v1

# PCI DSS v4.0 Requirement 1.1.1 — the procedure governing changes to network
# connections and to firewall/router configurations must be documented, kept
# current, and formally approved. The signed attestation must define the
# approval process, the authorized approver roles, and the ticket-reference
# convention, have been reviewed within the last year, and be signed. The
# procedure is collected from the repository via github/file_glob, so each
# matched file appears in input.change_control_procedure.docs with its fields
# plus a "path".

max_review_age_days := 365

required_fields := {
	"approval_process",
	"approver_roles",
	"ticket_reference_convention",
	"last_reviewed_at",
}

missing(obj, field) if not obj[field]

missing(obj, field) if obj[field] == ""

missing(obj, field) if obj[field] == []

missing(obj, field) if obj[field] == {}

deny contains msg if {
	not input.change_control_procedure
	msg := "no network change-control procedure found at policies/network-change-control-procedure.yaml (PCI DSS Requirement 1.1.1)"
}

deny contains msg if {
	input.change_control_procedure
	count(object.get(input.change_control_procedure, "docs", [])) == 0
	msg := "no network change-control procedure document found at policies/network-change-control-procedure.yaml (PCI DSS Requirement 1.1.1)"
}

deny contains msg if {
	some doc in input.change_control_procedure.docs
	some field in required_fields
	missing(doc, field)
	msg := sprintf("network change-control procedure is missing required field %q (PCI DSS Requirement 1.1.1)", [field])
}

deny contains msg if {
	some doc in input.change_control_procedure.docs
	doc.review_age_days > max_review_age_days
	msg := sprintf("network change-control procedure was last reviewed %d days ago; Requirement 1.1.1 requires the procedure be kept current (reviewed at least every %d days)", [doc.review_age_days, max_review_age_days])
}

deny contains msg if {
	some doc in input.change_control_procedure.docs
	not doc.signature_verified
	msg := "network change-control procedure signature did not verify (PCI DSS Requirement 1.1.1)"
}

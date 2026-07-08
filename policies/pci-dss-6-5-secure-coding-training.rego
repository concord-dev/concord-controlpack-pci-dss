package concord.pci_dss.pci_dss_6_5_secure_coding_training

import rego.v1

# PCI DSS Requirement 6.5 / v4.0 6.2.2 — developers trained in secure coding
# at least annually. The signed attestation must name the training program,
# the topics covered, how completion is tracked, and the date last delivered,
# and that delivery must be within the last 365 days (train_age <= 365 days).
# The attestation is collected via github/file_glob, so each matched file
# appears in input.secure_coding_training.docs with its signature_verified flag
# and its attested_fields object, plus a "path".

max_training_age_days := 365

required_fields := {
	"training_program",
	"topics",
	"completion_tracking",
	"last_delivered_at",
}

deny contains msg if {
	not input.secure_coding_training
	msg := "no secure-coding-training attestation collected"
}

deny contains msg if {
	input.secure_coding_training
	count(object.get(input.secure_coding_training, "docs", [])) == 0
	msg := "no secure-coding-training attestation document found at the configured repository path"
}

deny contains msg if {
	some doc in input.secure_coding_training.docs
	some field in required_fields
	field_missing(doc, field)
	msg := sprintf("secure-coding-training attestation missing required field: %s", [field])
}

deny contains msg if {
	some doc in input.secure_coding_training.docs
	not doc.signature_verified == true
	msg := "secure-coding-training attestation signature did not verify"
}

deny contains msg if {
	some doc in input.secure_coding_training.docs
	delivered_ns := time.parse_rfc3339_ns(doc.attested_fields.last_delivered_at)
	age_ns := time.now_ns() - delivered_ns
	age_ns > ((max_training_age_days * 24) * 3600) * 1000000000
	msg := sprintf("secure-coding training last delivered %s, exceeding the %d-day annual training interval", [doc.attested_fields.last_delivered_at, max_training_age_days])
}

# A required field is missing when it is absent, or present but empty.
field_missing(doc, field) if not doc.attested_fields[field]

field_missing(doc, field) if doc.attested_fields[field] == ""

field_missing(doc, field) if doc.attested_fields[field] == []

field_missing(doc, field) if doc.attested_fields[field] == {}

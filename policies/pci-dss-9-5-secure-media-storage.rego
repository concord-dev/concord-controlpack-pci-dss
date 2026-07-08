package concord.pci_dss.r_9_5

import rego.v1

# PCI DSS Requirement 9.5 — media containing cardholder data is stored securely
# and inventoried periodically. Physical media handling is not reachable as
# cloud telemetry, so Concord evaluates a signed, version-controlled
# attestation of the media-storage program. The attestation must be current
# (reviewed within the last 12 months), inventoried within the last 12 months,
# cosign-verified, and populated with the required program elements. The
# attestation is collected via github/file_glob, so each matched file appears
# in input.media_storage_attestation.docs with its fields plus a "path".

max_review_age_days := 365

max_inventory_age_days := 365

required_fields := {
	"storage_controls",
	"inventory_cadence",
	"last_inventory_at",
	"last_reviewed_at",
}

deny contains msg if {
	not input.media_storage_attestation
	msg := "no secure-media-storage attestation found (expected a signed attestation at policies/physical/media-storage.yaml)"
}

deny contains msg if {
	input.media_storage_attestation
	count(object.get(input.media_storage_attestation, "docs", [])) == 0
	msg := "no secure-media-storage attestation document found (expected a signed attestation at policies/physical/media-storage.yaml)"
}

deny contains msg if {
	some doc in input.media_storage_attestation.docs
	some field in required_fields
	unset(doc, field)
	msg := sprintf("secure-media-storage attestation is missing required field %q", [field])
}

deny contains msg if {
	some doc in input.media_storage_attestation.docs
	doc.review_age_days > max_review_age_days
	msg := sprintf("secure-media-storage attestation last reviewed %d days ago — PCI DSS Requirement 9.5 expects review at least every 12 months", [doc.review_age_days])
}

deny contains msg if {
	some doc in input.media_storage_attestation.docs
	doc.inventory_age_days > max_inventory_age_days
	msg := sprintf("secure-media-storage inventory last performed %d days ago — PCI DSS Requirement 9.5 expects a periodic (at least annual) media inventory", [doc.inventory_age_days])
}

deny contains msg if {
	some doc in input.media_storage_attestation.docs
	not doc.signature_verified
	msg := "secure-media-storage attestation cosign signature did not verify"
}

# unset treats an absent key, an empty string, and an empty array all as
# "not provided" so a stub attestation cannot silently satisfy a required field.
unset(obj, field) if not obj[field]

unset(obj, field) if obj[field] == ""

unset(obj, field) if {
	is_array(obj[field])
	count(obj[field]) == 0
}

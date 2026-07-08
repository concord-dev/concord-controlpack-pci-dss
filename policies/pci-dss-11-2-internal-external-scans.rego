package concord.pci_dss.internal_external_scans

import rego.v1

# PCI DSS v4.0 Requirement 11.3.1 / 11.3.2 (formerly 11.2) — internal and
# external vulnerability scans are performed at least every three months, with
# all critical findings resolved and a passing rescan; external scans are ASV
# performed. This is evidenced by a signed structured attestation of the scan
# cycle. Evidence: input.scan_attestation.
# Fails closed on a missing, unsigned, incomplete, stale, or dirty attestation.

max_scan_age_days := 92

required_fields := {
	"last_internal_scan_at",
	"last_external_scan_at",
	"scan_tool",
	"unresolved_criticals",
}

# A field is missing when absent, an empty string, or an empty array.
missing(obj, field) if not obj[field]

missing(obj, field) if obj[field] == ""

missing(obj, field) if obj[field] == []

# Fail closed: no attestation collected.
deny contains msg if {
	not input.scan_attestation
	msg := "no vulnerability-scan attestation collected — quarterly internal and external scans cannot be evidenced (PCI DSS 11.3, fail closed)"
}

# Every required field must be present and non-empty.
deny contains msg if {
	input.scan_attestation
	some field in required_fields
	missing(input.scan_attestation, field)
	msg := sprintf("scan attestation is missing required field %q (PCI DSS 11.3)", [field])
}

# The attestation must carry a verified signature.
deny contains msg if {
	input.scan_attestation
	not input.scan_attestation.signature_verified
	msg := "vulnerability-scan attestation is not signed by an authorised approver (PCI DSS 11.3)"
}

# Freshness must be provable: the scan-cycle age must be present.
deny contains msg if {
	input.scan_attestation
	not input.scan_attestation.test_age_days
	msg := "scan attestation does not record test_age_days — scan freshness cannot be verified (PCI DSS 11.3, fail closed)"
}

# The most recent scan cycle must be within the 92-day quarterly window.
deny contains msg if {
	input.scan_attestation.test_age_days > max_scan_age_days
	msg := sprintf("most recent vulnerability scan cycle is %d days old — PCI DSS 11.3 requires scans at least every %d days", [input.scan_attestation.test_age_days, max_scan_age_days])
}

# Unresolved critical findings mean the scan cycle is not clean.
deny contains msg if {
	input.scan_attestation.unresolved_criticals > 0
	msg := sprintf("%d critical vulnerability finding(s) remain unresolved — PCI DSS 11.3 requires remediation and a passing rescan", [input.scan_attestation.unresolved_criticals])
}

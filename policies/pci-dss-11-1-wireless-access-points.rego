package concord.pci_dss.r_11_1

import rego.v1

# PCI DSS Requirement 11.1 — quarterly testing for rogue wireless access points.
# Evaluated via a signed structured attestation: the statement must be complete,
# on an acceptable cadence, tested within the last quarter, and signed.

required_fields := {"test_cadence", "last_tested_at", "methodology", "responsible_role"}

acceptable_cadences := {"quarterly", "monthly", "weekly", "continuous"}

max_test_age_days := 92

deny contains msg if {
	not input.rogue_ap_testing
	msg := "no rogue wireless access-point testing attestation submitted"
}

deny contains msg if {
	att := input.rogue_ap_testing
	some f in required_fields
	not att[f]
	msg := sprintf("rogue-AP testing attestation is missing required field %q (PCI DSS Requirement 11.1)", [f])
}

deny contains msg if {
	att := input.rogue_ap_testing
	att.test_cadence
	not att.test_cadence in acceptable_cadences
	msg := sprintf("rogue-AP testing cadence %q is less frequent than the required quarterly schedule (PCI DSS Requirement 11.1)", [att.test_cadence])
}

deny contains msg if {
	att := input.rogue_ap_testing
	att.test_age_days > max_test_age_days
	msg := sprintf("last rogue-AP test was %d days ago, exceeding the %d-day (quarterly) maximum (PCI DSS Requirement 11.1)", [att.test_age_days, max_test_age_days])
}

deny contains msg if {
	att := input.rogue_ap_testing
	not att.signature_verified
	msg := "rogue-AP testing attestation is not signed or its signature could not be verified (PCI DSS Requirement 11.1)"
}

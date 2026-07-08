package concord.pci_dss.r_11_4

import rego.v1

# PCI DSS Requirement 11.4 — IDS/IPS monitors traffic across the CDE. Concord
# verifies AWS GuardDuty has an enabled detector in every active region and
# fails closed when no evidence or no active region is reported.

deny contains msg if {
	not input.intrusion_detection
	msg := "no intrusion-detection evidence collected"
}

deny contains msg if {
	input.intrusion_detection
	count(input.intrusion_detection.active_regions) == 0
	msg := "no active regions reported; IDS/IPS coverage of the CDE cannot be verified — failing closed (PCI DSS Requirement 11.4)"
}

deny contains msg if {
	some region in input.intrusion_detection.active_regions
	not has_enabled_detector(region)
	msg := sprintf("GuardDuty (IDS/IPS) is not enabled in active region %q that carries CDE traffic (PCI DSS Requirement 11.4)", [region])
}

has_enabled_detector(region) if {
	some d in input.intrusion_detection.guardduty_detectors
	d.region == region
	d.status == "ENABLED"
}

package concord.pci_dss.pci_dss_2_2_1_system_configuration_standards

import rego.v1

# PCI DSS v4.0 Requirement 2.2.1 — configuration standards must exist and be
# enforced. Technical proof in AWS: the Config recorder is recording in every
# active region, and at least one benchmark-aligned conformance pack is
# deployed and COMPLIANT. Fail-closed: missing evidence or missing packs deny.

deny contains msg if {
	not input.config_standards
	msg := "no AWS Config evidence collected"
}

deny contains msg if {
	some region in input.config_standards.active_regions
	not has_recording_in_region(region)
	msg := sprintf("AWS Config recorder is not recording in active region %q", [region])
}

deny contains msg if {
	input.config_standards
	count(object.get(input.config_standards, "conformance_packs", [])) == 0
	msg := "no benchmark-aligned Config conformance pack is deployed to enforce configuration standards"
}

deny contains msg if {
	some pack in input.config_standards.conformance_packs
	not pack.compliance_state == "COMPLIANT"
	msg := sprintf("Config conformance pack %q is %q (expected COMPLIANT)", [pack.name, object.get(pack, "compliance_state", "UNKNOWN")])
}

has_recording_in_region(region) if {
	some recorder in input.config_standards.recorders
	recorder.region == region
	recorder.recording == true
}

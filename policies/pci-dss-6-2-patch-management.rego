package concord.pci_dss.pci_dss_6_2_patch_management

import rego.v1

# PCI DSS Requirement 6.2 / v4.0 6.3.3 — critical and security patches applied
# within 30 days. Read from SSM Patch Manager. Fail-closed: an instance is
# denied unless it explicitly reports a COMPLIANT patch state, and any missing
# critical/security patch older than 30 days is denied per instance.

max_patch_age_days := 30

deny contains msg if {
	not input.patch_compliance
	msg := "no SSM patch-compliance evidence collected"
}

deny contains msg if {
	some instance in input.patch_compliance.instances
	not instance.compliance_status == "COMPLIANT"
	msg := sprintf("instance %q reports patch-compliance status %q (expected COMPLIANT)", [instance.instance_id, object.get(instance, "compliance_status", "UNKNOWN")])
}

deny contains msg if {
	some instance in input.patch_compliance.instances
	instance.oldest_missing_critical_age_days > max_patch_age_days
	msg := sprintf("instance %q has a missing critical/security patch %d days old (SLA %d days)", [instance.instance_id, instance.oldest_missing_critical_age_days, max_patch_age_days])
}

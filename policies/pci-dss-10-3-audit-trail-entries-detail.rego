package concord.pci_dss.r_10_3

import rego.v1

# PCI DSS Requirement 10.3 — audit-trail entries must record user identity,
# event type, timestamp, origin, and affected resource, and be tamper-evident.
# Concord verifies the CloudTrail flags that make entries complete and
# trustworthy and fails closed when no trail is present.

trails := input.audit_trail_detail.cloudtrail.trails

deny contains msg if {
	not input.audit_trail_detail
	msg := "no audit-trail evidence collected"
}

deny contains msg if {
	input.audit_trail_detail
	count(trails) == 0
	msg := "no CloudTrail trail present; audit-trail entry detail cannot be verified — failing closed (PCI DSS Requirement 10.3)"
}

deny contains msg if {
	some trail in trails
	not trail.include_global_service_events
	msg := sprintf("CloudTrail trail %q excludes global service events; user identity and origin for IAM/STS actions are not recorded (PCI DSS Requirement 10.3.1)", [trail.name])
}

deny contains msg if {
	some trail in trails
	not trail.include_management_events
	msg := sprintf("CloudTrail trail %q does not record management events; event source and name are not captured (PCI DSS Requirement 10.3.1)", [trail.name])
}

deny contains msg if {
	some trail in trails
	not trail.log_file_validation_enabled
	msg := sprintf("CloudTrail trail %q has log-file validation disabled; audit-trail entries are not tamper-evident (PCI DSS Requirement 10.3.2)", [trail.name])
}

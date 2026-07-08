package concord.pci_dss.r_10_1

import rego.v1

# PCI DSS Requirement 10.1 — audit trails link all access to system components
# to individual users. Fail closed unless a multi-region CloudTrail trail is
# enabled and actively logging.

trails := input.audit_trail.cloudtrail.trails

deny contains msg if {
	not input.audit_trail
	msg := "no audit-trail evidence collected"
}

deny contains msg if {
	input.audit_trail
	count(trails) == 0
	msg := "no CloudTrail trail is configured; system components do not produce an audit trail (PCI DSS Requirement 10.1)"
}

deny contains msg if {
	input.audit_trail
	count(trails) > 0
	not has_multi_region_logging_trail
	msg := "no multi-region CloudTrail trail is both enabled and logging; account activity is not linked to individual users (PCI DSS Requirement 10.1)"
}

deny contains msg if {
	some trail in trails
	trail.is_multi_region_trail
	not trail.is_logging
	msg := sprintf("multi-region CloudTrail trail %q is not currently logging; audit trail is incomplete (PCI DSS Requirement 10.1)", [trail.name])
}

has_multi_region_logging_trail if {
	some trail in trails
	trail.is_multi_region_trail
	trail.is_logging
}

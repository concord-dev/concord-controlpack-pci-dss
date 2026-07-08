package concord.pci_dss.r_10_2

import rego.v1

# PCI DSS Requirement 10.2 — required events are captured. CloudTrail must log
# management events for both read and write activity and record at least one
# data-event selector. Each missing category denies independently. Fail closed
# when no evidence is present.

trails := input.cloudtrail_events.trails

deny contains msg if {
	not input.cloudtrail_events
	msg := "no CloudTrail event-selector evidence collected"
}

deny contains msg if {
	input.cloudtrail_events
	not mgmt_read_logged
	msg := "CloudTrail is not logging management (control-plane) read events; privileged read activity is not captured (PCI DSS Requirement 10.2.1)"
}

deny contains msg if {
	input.cloudtrail_events
	not mgmt_write_logged
	msg := "CloudTrail is not logging management (control-plane) write events; privileged change activity is not captured (PCI DSS Requirement 10.2.1)"
}

deny contains msg if {
	input.cloudtrail_events
	not data_events_logged
	msg := "CloudTrail has no data-event selector; data-plane access to stored cardholder data is not captured (PCI DSS Requirement 10.2.1.1)"
}

mgmt_read_logged if {
	some trail in trails
	some sel in trail.event_selectors
	sel.include_management_events == true
	sel.read_write_type in {"All", "ReadOnly"}
}

mgmt_write_logged if {
	some trail in trails
	some sel in trail.event_selectors
	sel.include_management_events == true
	sel.read_write_type in {"All", "WriteOnly"}
}

data_events_logged if {
	some trail in trails
	some sel in trail.event_selectors
	count(sel.data_resources) > 0
}

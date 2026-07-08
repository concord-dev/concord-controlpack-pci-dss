package concord.pci_dss.r_10_6

import rego.v1

# PCI DSS Requirement 10.6 — security events are reviewed for anomalies.
# Concord verifies CloudWatch metric alarms (an accepted automated review
# mechanism) cover every required security-event category and that each alarm
# has a wired-up notification action. Fail closed when no evidence is present.

required_categories := {
	"unauthorized_api_calls",
	"root_account_usage",
	"iam_policy_changes",
	"console_signin_failures",
}

deny contains msg if {
	not input.log_review
	msg := "no CloudWatch metric-alarm evidence collected"
}

deny contains msg if {
	input.log_review
	some cat in required_categories
	not covered(cat)
	msg := sprintf("no CloudWatch metric alarm with an active notification reviews security-event category %q (PCI DSS Requirement 10.6)", [cat])
}

deny contains msg if {
	some a in input.log_review.metric_alarms
	a.alarm_configured == true
	count(a.alarm_actions) == 0
	msg := sprintf("CloudWatch metric alarm %q has no notification action; %q events would not surface for review (PCI DSS Requirement 10.6.1)", [a.name, a.covers])
}

covered(cat) if {
	some a in input.log_review.metric_alarms
	a.covers == cat
	a.alarm_configured == true
	count(a.alarm_actions) > 0
}

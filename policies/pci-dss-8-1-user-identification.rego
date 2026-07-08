package concord.pci_dss.user_identification

import rego.v1

# PCI DSS v4.0 Requirement 8.1 / 8.2.1 — every user is assigned a unique ID
# before access is granted so that actions are traceable to an individual.
# Evidence: AWS IAM credential report (input.iam_credentials.users[]).
# Fails console-enabled shared/generic accounts and routine root usage.

# Names that indicate a shared, group, or generic (non-individual) account.
generic_patterns := {
	"admin",
	"administrator",
	"shared",
	"service",
	"svc",
	"generic",
	"team",
	"group",
	"operator",
	"guest",
}

# Root is treated as "used routinely" when its console password was used
# within this window (days). An explicit day-count keeps the check
# time-independent.
routine_use_days := 30

is_generic(name) if {
	some pattern in generic_patterns
	contains(lower(name), pattern)
}

# Fail closed: no credential report means uniqueness cannot be demonstrated.
deny contains msg if {
	not input.iam_credentials
	msg := "no IAM credential report collected — cannot demonstrate that every user is uniquely identified (PCI DSS 8.1)"
}

# Console-enabled account with a shared/generic name.
deny contains msg if {
	some u in input.iam_credentials.users
	u.user != "<root_account>"
	u.password_enabled == true
	is_generic(u.user)
	msg := sprintf("IAM user %q has a shared/generic name with console access — access must be tied to a unique, named individual (PCI DSS 8.1)", [u.user])
}

# Root account used for routine console operations.
deny contains msg if {
	some u in input.iam_credentials.users
	u.user == "<root_account>"
	u.password_enabled == true
	u.password_last_used_days_ago <= routine_use_days
	msg := sprintf("root account was used %d day(s) ago — root must not be used for routine operations, which breaks individual accountability (PCI DSS 8.1)", [u.password_last_used_days_ago])
}

# Root account holding a long-lived programmatic credential.
deny contains msg if {
	some u in input.iam_credentials.users
	u.user == "<root_account>"
	some k in u.access_keys
	k.active == true
	msg := "root account has an active access key — root must have no standing credentials and must not be used routinely (PCI DSS 8.1)"
}

package concord.pci_dss.no_shared_accounts

import rego.v1

# PCI DSS v4.0 Requirement 8.5 / 8.2.2 — shared, group, or generic accounts
# must not be used to administer or access the cardholder data environment.
# Evidence: AWS IAM credential report (input.iam_credentials.users[]).
# Any account with a shared/generic name that still holds a live credential
# (enabled console password or an active access key) is denied.

# Naming patterns that indicate a shared, group, or generic account.
shared_account_patterns := {
	"shared",
	"service",
	"svc",
	"group",
	"team",
	"generic",
	"functional",
	"admin",
	"administrator",
	"ops-team",
}

is_shared(name) if {
	some pattern in shared_account_patterns
	contains(lower(name), pattern)
}

has_active_access_key(u) if {
	some k in u.access_keys
	k.active == true
}

has_live_credential(u) if u.password_enabled == true

has_live_credential(u) if has_active_access_key(u)

credential_kind(u) := "console password" if u.password_enabled == true

credential_kind(u) := "active access key" if {
	not u.password_enabled == true
	has_active_access_key(u)
}

# Fail closed: no credential report means shared accounts cannot be ruled out.
deny contains msg if {
	not input.iam_credentials
	msg := "no IAM credential report collected — cannot verify that no shared or generic accounts are in use (PCI DSS 8.5)"
}

# Shared/generic account that still holds a usable credential.
deny contains msg if {
	some u in input.iam_credentials.users
	u.user != "<root_account>"
	is_shared(u.user)
	has_live_credential(u)
	msg := sprintf("account %q matches a shared/generic naming pattern and holds a live credential (%s) — shared or group accounts must not be used, especially for administration (PCI DSS 8.5)", [u.user, credential_kind(u)])
}

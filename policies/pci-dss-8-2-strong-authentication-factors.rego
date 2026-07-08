package concord.pci_dss.strong_authentication_factors

import rego.v1

# PCI DSS v4.0 Requirement 8.2 / 8.4.1 — interactive, remote, and
# administrative access must use at least two authentication factors. For AWS
# console access this is a password plus a registered MFA device.
# Evidence: AWS IAM credential report (input.iam_credentials.users[]).
# Fails closed: mfa_active that is false, null, or absent is treated as "no
# second factor" via `not u.mfa_active`.

# Fail closed: no credential report means the second factor cannot be proven.
deny contains msg if {
	not input.iam_credentials
	msg := "no IAM credential report collected — cannot verify at least two authentication factors (PCI DSS 8.2)"
}

# Console-enabled, non-root user without an active MFA device (single factor).
deny contains msg if {
	some u in input.iam_credentials.users
	u.user != "<root_account>"
	u.password_enabled == true
	not u.mfa_active
	msg := sprintf("IAM user %q has console (password) access with no active MFA device — PCI DSS 8.2 requires at least two authentication factors; enroll MFA", [u.user])
}

# Root's authentication is covered by Requirement 8.1; advise if console-enabled.
warn contains msg if {
	some u in input.iam_credentials.users
	u.user == "<root_account>"
	u.password_enabled == true
	msg := "root account has console access — evaluate under PCI DSS 8.1 and prefer federated administrative access"
}

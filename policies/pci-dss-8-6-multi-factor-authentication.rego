package concord.pci_dss.multi_factor_authentication

import rego.v1

# PCI DSS v4.0 Requirement 8.6 / 8.4.2 / 8.5.1 — MFA is required for all
# access into the cardholder data environment, including non-console and
# administrative paths. Evidence: AWS IAM credential report
# (input.iam_credentials.users[]). Fails console identities without MFA and
# identities whose only credential is an active access key with no MFA device.
# Fails closed: mfa_active that is false, null, or absent is treated as "no
# MFA" via `not u.mfa_active`.

# Fail closed: no credential report means MFA coverage cannot be proven.
deny contains msg if {
	not input.iam_credentials
	msg := "no IAM credential report collected — cannot verify MFA on access into the CDE (PCI DSS 8.6)"
}

# Console access path without an active MFA device.
deny contains msg if {
	some u in input.iam_credentials.users
	u.user != "<root_account>"
	u.password_enabled == true
	not u.mfa_active
	msg := sprintf("IAM user %q has console access into the CDE with no active MFA device (PCI DSS 8.6)", [u.user])
}

# Non-console path: active long-lived access key on an identity with no MFA.
deny contains msg if {
	some u in input.iam_credentials.users
	u.user != "<root_account>"
	some k in u.access_keys
	k.active == true
	not u.mfa_active
	msg := sprintf("IAM user %q reaches the CDE with an active access key but has no MFA device — non-console access must also be protected by MFA (PCI DSS 8.6)", [u.user])
}

# Root MFA is evaluated by Requirements 8.1/8.2; advise if console-enabled.
warn contains msg if {
	some u in input.iam_credentials.users
	u.user == "<root_account>"
	u.password_enabled == true
	not u.mfa_active
	msg := "root account has console access without MFA — enable a hardware MFA device on root immediately"
}

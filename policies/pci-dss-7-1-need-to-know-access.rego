package concord.pci_dss.need_to_know_access

import rego.v1

# PCI DSS v4.0 Requirement 7.1 / 7.2.1 — access to system components and
# cardholder data is restricted to the least privileges necessary for an
# individual's job classification and function ("need to know"). Every IAM
# identity must avoid standing full-admin grants: neither the AWS-managed
# AdministratorAccess policy nor an inline/managed Allow of Action "*" on
# Resource "*". Adapted from CIS AWS Foundations 1.16 and mirrors the PCI 7.2
# least-privilege posture.
# Evidence: input.iam_policies.identities[].attached_policies[].

# Fail closed: without policy evidence, least-privilege cannot be demonstrated.
deny contains msg if {
	not input.iam_policies
	msg := "no IAM policy evidence collected — cannot demonstrate that access is restricted to least privilege (PCI DSS 7.1)"
}

# Attached to the AWS-managed AdministratorAccess policy.
deny contains msg if {
	some id in input.iam_policies.identities
	some p in id.attached_policies
	p.policy_name == "AdministratorAccess"
	msg := sprintf("IAM %s %q is attached to AdministratorAccess — full-admin access is not restricted by job function (PCI DSS 7.1)", [identity_type(id), id.name])
}

# Attached to any policy that allows Action "*" on Resource "*".
deny contains msg if {
	some id in input.iam_policies.identities
	some p in id.attached_policies
	some stmt in p.document.Statement
	stmt.Effect == "Allow"
	action_is_wildcard(stmt)
	resource_is_wildcard(stmt)
	msg := sprintf("IAM %s %q attaches policy %q allowing Action \"*\" on Resource \"*\" — grant is broader than any job function requires (PCI DSS 7.1)", [identity_type(id), id.name, p.policy_name])
}

identity_type(id) := id.type

identity_type(id) := "identity" if not id.type

action_is_wildcard(stmt) if stmt.Action == "*"

action_is_wildcard(stmt) if {
	some a in stmt.Action
	a == "*"
}

resource_is_wildcard(stmt) if stmt.Resource == "*"

resource_is_wildcard(stmt) if {
	some r in stmt.Resource
	r == "*"
}

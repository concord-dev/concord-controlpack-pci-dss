package concord.pci_dss.access_control_system

import rego.v1

# PCI DSS v4.0 Requirement 7.3 / 7.3.3 — the access-control system must cover
# all system components and default to "deny all". This policy inspects IAM
# policy statements for constructs that subvert deny-by-default:
#   * an Allow of Action "*" on Resource "*" (explicit allow-all), and
#   * an Allow that uses NotAction or NotResource ("allow everything except"),
#     which fails open as new actions/resources appear.
# Evidence: input.iam_policies.identities[].attached_policies[].document.Statement[].

# Fail closed: without policy evidence the deny-by-default posture is unproven.
deny contains msg if {
	not input.iam_policies
	msg := "no IAM policy evidence collected — cannot verify the access-control system defaults to deny-all (PCI DSS 7.3)"
}

# Explicit allow-all statement contradicts the deny-all default.
deny contains msg if {
	some id in input.iam_policies.identities
	some p in id.attached_policies
	some stmt in p.document.Statement
	stmt.Effect == "Allow"
	action_is_wildcard(stmt)
	resource_is_wildcard(stmt)
	msg := sprintf("IAM %s %q policy %q allows Action \"*\" on Resource \"*\" — an explicit allow-all defeats the required deny-all default (PCI DSS 7.3.3)", [identity_type(id), id.name, p.policy_name])
}

# Allow + NotAction inverts the model to "allow every action except ..." and
# therefore fails open, re-opening the default-deny baseline.
deny contains msg if {
	some id in input.iam_policies.identities
	some p in id.attached_policies
	some stmt in p.document.Statement
	stmt.Effect == "Allow"
	stmt.NotAction
	msg := sprintf("IAM %s %q policy %q uses Allow + NotAction — this allows every action except a deny-list and subverts deny-by-default (PCI DSS 7.3.3)", [identity_type(id), id.name, p.policy_name])
}

# Allow + NotResource inverts the model to "allow on every resource except ..."
# and likewise fails open for any new resource.
deny contains msg if {
	some id in input.iam_policies.identities
	some p in id.attached_policies
	some stmt in p.document.Statement
	stmt.Effect == "Allow"
	stmt.NotResource
	msg := sprintf("IAM %s %q policy %q uses Allow + NotResource — this allows access to every resource except a deny-list and subverts deny-by-default (PCI DSS 7.3.3)", [identity_type(id), id.name, p.policy_name])
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

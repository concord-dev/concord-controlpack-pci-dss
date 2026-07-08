package concord.pci_dss.r_1_3_1

import rego.v1

# PCI DSS v4.0 Requirement 1.3.1 — inbound traffic to the CDE is restricted to
# only necessary traffic; all other traffic is specifically denied. Security
# groups that protect these tiers must never permit direct ingress from an
# untrusted network.
protected_tiers := {"cde", "private"}

untrusted_cidr("0.0.0.0/0")

untrusted_cidr("::/0")

deny contains msg if {
	not input.security_groups
	msg := "no security-group evidence collected"
}

deny contains msg if {
	some sg in input.security_groups.groups
	sg.scope in protected_tiers
	some rule in sg.ingress_rules
	untrusted_cidr(rule.cidr)
	msg := sprintf("security group %q protects a %s-tier resource but permits direct inbound from the untrusted network %q; the perimeter must specifically deny all direct Internet access to private and CDE resources (PCI DSS Requirement 1.3.1)", [sg.id, sg.scope, rule.cidr])
}

# Fail closed: a security group whose protected tier is not declared cannot be
# shown to sit on the trusted side of the perimeter.
deny contains msg if {
	some sg in input.security_groups.groups
	not sg.scope
	msg := sprintf("security group %q does not declare the network tier it protects; every group must be classified so CDE and private tiers can be confirmed isolated from untrusted networks (PCI DSS Requirement 1.3.1)", [sg.id])
}

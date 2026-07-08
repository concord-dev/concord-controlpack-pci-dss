package concord.pci_dss.r_1_2_1

import rego.v1

# PCI DSS v4.0 Requirement 1.2.1 — NSC rulesets must permit only necessary
# traffic and deny everything else. Only these ports may face the untrusted
# Internet (0.0.0.0/0); any other Internet-facing ingress is a violation.
allowed_public_ports := {80, 443}

deny contains msg if {
	not input.security_groups
	msg := "no security-group evidence collected"
}

# A rule open to the Internet that does not declare explicit port bounds opens
# every port and therefore cannot be on the allow-list (fail closed).
deny contains msg if {
	some sg in input.security_groups.groups
	some rule in sg.ingress_rules
	rule.cidr == "0.0.0.0/0"
	not has_port_bounds(rule)
	msg := sprintf("security group %q allows all inbound traffic from 0.0.0.0/0 with no port restriction; NSC rulesets must permit only the allow-listed necessary services 80/443 and deny all other traffic (PCI DSS Requirement 1.2.1)", [sg.id])
}

# A bounded Internet-facing rule is permitted only when it opens exactly one
# allow-listed port. Single non-allow-listed ports and any multi-port range are
# reported.
deny contains msg if {
	some sg in input.security_groups.groups
	some rule in sg.ingress_rules
	rule.cidr == "0.0.0.0/0"
	has_port_bounds(rule)
	not allowed_public_rule(rule)
	msg := sprintf("security group %q allows 0.0.0.0/0 inbound to ports %d-%d, which are not limited to the allow-list of necessary public services 80/443 (PCI DSS Requirement 1.2.1)", [sg.id, rule.from_port, rule.to_port])
}

has_port_bounds(rule) if {
	is_number(rule.from_port)
	is_number(rule.to_port)
}

allowed_public_rule(rule) if {
	rule.from_port == rule.to_port
	rule.from_port in allowed_public_ports
}

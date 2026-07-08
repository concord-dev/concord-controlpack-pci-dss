package concord.pci_dss.r_2_3

import rego.v1

# PCI DSS v4.0 Requirement 2.3 — all non-console administrative access must be
# encrypted with strong cryptography. These ports carry administrative sessions
# in cleartext and must never be permitted.
cleartext_admin_ports := {
	23: "Telnet",
	512: "rexec",
	513: "rlogin",
	514: "rsh",
	2323: "Telnet (alternate)",
	5900: "unencrypted VNC",
	6000: "unencrypted X11",
}

deny contains msg if {
	not input.security_groups
	msg := "no security-group evidence collected"
}

deny contains msg if {
	some sg in input.security_groups.groups
	some rule in sg.ingress_rules
	some port, name in cleartext_admin_ports
	port_in_range(port, rule)
	msg := sprintf("security group %q permits %s (port %d) for administrative access; PCI DSS Requirement 2.3 requires all non-console administrative access to use strong cryptography such as SSH or TLS", [sg.id, name, port])
}

# Fail closed: any rule flagged as administrative must affirm that it is
# encrypted. A missing or false encryption status is a violation (catches, for
# example, RDP or web administration exposed without TLS).
deny contains msg if {
	some sg in input.security_groups.groups
	some rule in sg.ingress_rules
	rule.admin == true
	not rule.encrypted == true
	msg := sprintf("security group %q exposes an administrative service on ports %d-%d that is not confirmed to use encryption; non-console administrative access must use strong cryptography (PCI DSS Requirement 2.3)", [sg.id, rule.from_port, rule.to_port])
}

port_in_range(port, rule) if {
	rule.from_port <= port
	rule.to_port >= port
}

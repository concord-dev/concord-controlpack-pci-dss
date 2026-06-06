package concord.pci_dss.r_1_2

import rego.v1

sensitive_ports := {22, 3389, 3306, 5432, 6379, 9200, 27017}

deny contains msg if {
    not input.security_groups
    msg := "no security-group evidence collected"
}

deny contains msg if {
    some sg in input.security_groups.groups
    some rule in sg.ingress_rules
    rule.cidr == "0.0.0.0/0"
    some port in sensitive_ports
    port_in_range(port, rule)
    msg := sprintf("security group %q exposes port %d to 0.0.0.0/0", [sg.id, port])
}

port_in_range(port, rule) if {
    rule.from_port <= port
    rule.to_port >= port
}

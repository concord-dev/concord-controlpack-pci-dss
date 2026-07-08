package concord.pci_dss.r_1_4_1

import rego.v1

# PCI DSS v4.0 Requirement 1.4.1 — NSCs between trusted and untrusted networks
# must fail closed. Each network ACL must carry an explicit deny-all catch-all
# on both directions so traffic that is not expressly permitted is dropped.

deny contains msg if {
	not input.network_acls
	msg := "no network-ACL evidence collected"
}

deny contains msg if {
	input.network_acls
	count(input.network_acls.acls) == 0
	msg := "no network ACLs found; the boundary between trusted and untrusted networks is not enforced by any NSC (PCI DSS Requirement 1.4.1)"
}

deny contains msg if {
	some acl in input.network_acls.acls
	not has_default_deny(acl, false)
	msg := sprintf("network ACL %q has no explicit inbound deny-all rule; NSCs must fail closed and specifically deny all inbound traffic that is not expressly permitted (PCI DSS Requirement 1.4.1)", [acl.id])
}

deny contains msg if {
	some acl in input.network_acls.acls
	not has_default_deny(acl, true)
	msg := sprintf("network ACL %q has no explicit outbound deny-all rule; the boundary must fail closed on egress as well as ingress (PCI DSS Requirement 1.4.1)", [acl.id])
}

has_default_deny(acl, egress_flag) if {
	some entry in acl.entries
	entry.egress == egress_flag
	entry.action == "deny"
	entry.cidr == "0.0.0.0/0"
	catch_all_protocol(entry)
}

catch_all_protocol(entry) if entry.protocol == "-1"

catch_all_protocol(entry) if entry.protocol == "all"

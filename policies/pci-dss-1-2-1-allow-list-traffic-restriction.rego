package concord.pci_dss.pci_dss_1_2_1_allow_list_traffic_restriction

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_1_2_1_allow_list_traffic_restriction")
	msg := "PCI-DSS-1.2.1-allow-list-traffic-restriction: aws evidence missing"
}

deny contains msg if {
	some r in input.pci_dss_1_2_1_allow_list_traffic_restriction.resources
	not r.compliant
	msg := sprintf("PCI-DSS-1.2.1-allow-list-traffic-restriction: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

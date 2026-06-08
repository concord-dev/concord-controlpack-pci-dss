package concord.pci_dss.pci_dss_1_3_1_perimeter_firewall

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_1_3_1_perimeter_firewall")
	msg := "PCI-DSS-1.3.1-perimeter-firewall: aws evidence missing"
}

deny contains msg if {
	some r in input.pci_dss_1_3_1_perimeter_firewall.resources
	not r.compliant
	msg := sprintf("PCI-DSS-1.3.1-perimeter-firewall: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

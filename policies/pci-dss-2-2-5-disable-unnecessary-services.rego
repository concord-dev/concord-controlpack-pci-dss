package concord.pci_dss.pci_dss_2_2_5_disable_unnecessary_services

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_2_2_5_disable_unnecessary_services")
	msg := "PCI-DSS-2.2.5-disable-unnecessary-services: aws evidence missing"
}

deny contains msg if {
	some r in input.pci_dss_2_2_5_disable_unnecessary_services.resources
	not r.compliant
	msg := sprintf("PCI-DSS-2.2.5-disable-unnecessary-services: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

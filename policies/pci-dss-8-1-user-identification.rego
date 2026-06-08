package concord.pci_dss.pci_dss_8_1_user_identification

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_8_1_user_identification")
	msg := "PCI-DSS-8.1-user-identification: aws evidence missing"
}

deny contains msg if {
	some r in input.pci_dss_8_1_user_identification.resources
	not r.compliant
	msg := sprintf("PCI-DSS-8.1-user-identification: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

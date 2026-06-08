package concord.pci_dss.pci_dss_3_6_1_key_rotation

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_3_6_1_key_rotation")
	msg := "PCI-DSS-3.6.1-key-rotation: aws evidence missing"
}

deny contains msg if {
	some r in input.pci_dss_3_6_1_key_rotation.resources
	not r.compliant
	msg := sprintf("PCI-DSS-3.6.1-key-rotation: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

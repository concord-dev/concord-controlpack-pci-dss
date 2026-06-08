package concord.pci_dss.pci_dss_11_4_intrusion_detection

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_11_4_intrusion_detection")
	msg := "PCI-DSS-11.4-intrusion-detection: aws evidence missing"
}

deny contains msg if {
	some r in input.pci_dss_11_4_intrusion_detection.resources
	not r.compliant
	msg := sprintf("PCI-DSS-11.4-intrusion-detection: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

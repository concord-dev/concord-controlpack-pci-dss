package concord.pci_dss.pci_dss_1_4_1_stateful_inspection

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_1_4_1_stateful_inspection")
	msg := "PCI-DSS-1.4.1-stateful-inspection: aws evidence missing"
}

deny contains msg if {
	some r in input.pci_dss_1_4_1_stateful_inspection.resources
	not r.compliant
	msg := sprintf("PCI-DSS-1.4.1-stateful-inspection: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

package concord.pci_dss.pci_dss_7_3_access_control_system

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_7_3_access_control_system")
	msg := "PCI-DSS-7.3-access-control-system: aws evidence missing"
}

deny contains msg if {
	some r in input.pci_dss_7_3_access_control_system.resources
	not r.compliant
	msg := sprintf("PCI-DSS-7.3-access-control-system: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

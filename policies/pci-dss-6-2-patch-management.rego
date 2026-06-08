package concord.pci_dss.pci_dss_6_2_patch_management

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_6_2_patch_management")
	msg := "PCI-DSS-6.2-patch-management: aws evidence missing"
}

deny contains msg if {
	some r in input.pci_dss_6_2_patch_management.resources
	not r.compliant
	msg := sprintf("PCI-DSS-6.2-patch-management: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

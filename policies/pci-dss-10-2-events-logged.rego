package concord.pci_dss.pci_dss_10_2_events_logged

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_10_2_events_logged")
	msg := "PCI-DSS-10.2-events-logged: aws evidence missing"
}

deny contains msg if {
	some r in input.pci_dss_10_2_events_logged.resources
	not r.compliant
	msg := sprintf("PCI-DSS-10.2-events-logged: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

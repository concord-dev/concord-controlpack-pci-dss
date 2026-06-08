package concord.pci_dss.pci_dss_10_1_audit_trail_implementation

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_10_1_audit_trail_implementation")
	msg := "PCI-DSS-10.1-audit-trail-implementation: aws evidence missing"
}

deny contains msg if {
	some r in input.pci_dss_10_1_audit_trail_implementation.resources
	not r.compliant
	msg := sprintf("PCI-DSS-10.1-audit-trail-implementation: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

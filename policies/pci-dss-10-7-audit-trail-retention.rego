package concord.pci_dss.pci_dss_10_7_audit_trail_retention

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_10_7_audit_trail_retention")
	msg := "PCI-DSS-10.7-audit-trail-retention: aws evidence missing"
}

deny contains msg if {
	some r in input.pci_dss_10_7_audit_trail_retention.resources
	not r.compliant
	msg := sprintf("PCI-DSS-10.7-audit-trail-retention: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

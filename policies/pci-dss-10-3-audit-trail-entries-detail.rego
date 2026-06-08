package concord.pci_dss.pci_dss_10_3_audit_trail_entries_detail

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_10_3_audit_trail_entries_detail")
	msg := "PCI-DSS-10.3-audit-trail-entries-detail: aws evidence missing"
}

deny contains msg if {
	some r in input.pci_dss_10_3_audit_trail_entries_detail.resources
	not r.compliant
	msg := sprintf("PCI-DSS-10.3-audit-trail-entries-detail: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

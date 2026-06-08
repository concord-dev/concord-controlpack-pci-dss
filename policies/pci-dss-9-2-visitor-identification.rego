package concord.pci_dss.pci_dss_9_2_visitor_identification

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_9_2_visitor_identification")
	msg := "PCI-DSS-9.2-visitor-identification: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.pci_dss_9_2_visitor_identification)
	msg := sprintf("PCI-DSS-9.2-visitor-identification: attestation expired (expires_at=%s)", [input.pci_dss_9_2_visitor_identification.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.pci_dss_9_2_visitor_identification, 365)
	msg := sprintf("PCI-DSS-9.2-visitor-identification: attestation not reviewed in 365 days (last_review_at=%s)", [input.pci_dss_9_2_visitor_identification.last_review_at])
}

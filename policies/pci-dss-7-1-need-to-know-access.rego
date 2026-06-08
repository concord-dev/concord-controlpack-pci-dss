package concord.pci_dss.pci_dss_7_1_need_to_know_access

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_7_1_need_to_know_access")
	msg := "PCI-DSS-7.1-need-to-know-access: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.pci_dss_7_1_need_to_know_access)
	msg := sprintf("PCI-DSS-7.1-need-to-know-access: attestation expired (expires_at=%s)", [input.pci_dss_7_1_need_to_know_access.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.pci_dss_7_1_need_to_know_access, 365)
	msg := sprintf("PCI-DSS-7.1-need-to-know-access: attestation not reviewed in 365 days (last_review_at=%s)", [input.pci_dss_7_1_need_to_know_access.last_review_at])
}

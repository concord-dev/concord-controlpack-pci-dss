package concord.pci_dss.pci_dss_6_4_change_control

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_6_4_change_control")
	msg := "PCI-DSS-6.4-change-control: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.pci_dss_6_4_change_control)
	msg := sprintf("PCI-DSS-6.4-change-control: attestation expired (expires_at=%s)", [input.pci_dss_6_4_change_control.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.pci_dss_6_4_change_control, 365)
	msg := sprintf("PCI-DSS-6.4-change-control: attestation not reviewed in 365 days (last_review_at=%s)", [input.pci_dss_6_4_change_control.last_review_at])
}

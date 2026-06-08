package concord.pci_dss.pci_dss_9_1_physical_access_controls

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_9_1_physical_access_controls")
	msg := "PCI-DSS-9.1-physical-access-controls: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.pci_dss_9_1_physical_access_controls)
	msg := sprintf("PCI-DSS-9.1-physical-access-controls: attestation expired (expires_at=%s)", [input.pci_dss_9_1_physical_access_controls.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.pci_dss_9_1_physical_access_controls, 365)
	msg := sprintf("PCI-DSS-9.1-physical-access-controls: attestation not reviewed in 365 days (last_review_at=%s)", [input.pci_dss_9_1_physical_access_controls.last_review_at])
}

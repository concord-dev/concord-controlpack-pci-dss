package concord.pci_dss.pci_dss_3_5_1_key_management_procedures

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_3_5_1_key_management_procedures")
	msg := "PCI-DSS-3.5.1-key-management-procedures: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.pci_dss_3_5_1_key_management_procedures)
	msg := sprintf("PCI-DSS-3.5.1-key-management-procedures: attestation expired (expires_at=%s)", [input.pci_dss_3_5_1_key_management_procedures.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.pci_dss_3_5_1_key_management_procedures, 365)
	msg := sprintf("PCI-DSS-3.5.1-key-management-procedures: attestation not reviewed in 365 days (last_review_at=%s)", [input.pci_dss_3_5_1_key_management_procedures.last_review_at])
}

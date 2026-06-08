package concord.pci_dss.pci_dss_6_5_secure_coding_training

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_6_5_secure_coding_training")
	msg := "PCI-DSS-6.5-secure-coding-training: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.pci_dss_6_5_secure_coding_training)
	msg := sprintf("PCI-DSS-6.5-secure-coding-training: attestation expired (expires_at=%s)", [input.pci_dss_6_5_secure_coding_training.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.pci_dss_6_5_secure_coding_training, 365)
	msg := sprintf("PCI-DSS-6.5-secure-coding-training: attestation not reviewed in 365 days (last_review_at=%s)", [input.pci_dss_6_5_secure_coding_training.last_review_at])
}

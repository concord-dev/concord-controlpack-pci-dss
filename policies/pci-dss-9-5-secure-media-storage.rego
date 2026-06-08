package concord.pci_dss.pci_dss_9_5_secure_media_storage

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_9_5_secure_media_storage")
	msg := "PCI-DSS-9.5-secure-media-storage: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.pci_dss_9_5_secure_media_storage)
	msg := sprintf("PCI-DSS-9.5-secure-media-storage: attestation expired (expires_at=%s)", [input.pci_dss_9_5_secure_media_storage.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.pci_dss_9_5_secure_media_storage, 365)
	msg := sprintf("PCI-DSS-9.5-secure-media-storage: attestation not reviewed in 365 days (last_review_at=%s)", [input.pci_dss_9_5_secure_media_storage.last_review_at])
}

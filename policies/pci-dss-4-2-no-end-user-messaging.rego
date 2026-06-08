package concord.pci_dss.pci_dss_4_2_no_end_user_messaging

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_4_2_no_end_user_messaging")
	msg := "PCI-DSS-4.2-no-end-user-messaging: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.pci_dss_4_2_no_end_user_messaging)
	msg := sprintf("PCI-DSS-4.2-no-end-user-messaging: attestation expired (expires_at=%s)", [input.pci_dss_4_2_no_end_user_messaging.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.pci_dss_4_2_no_end_user_messaging, 365)
	msg := sprintf("PCI-DSS-4.2-no-end-user-messaging: attestation not reviewed in 365 days (last_review_at=%s)", [input.pci_dss_4_2_no_end_user_messaging.last_review_at])
}

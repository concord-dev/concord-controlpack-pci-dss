package concord.pci_dss.pci_dss_3_1_cardholder_data_retention

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_3_1_cardholder_data_retention")
	msg := "PCI-DSS-3.1-cardholder-data-retention: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.pci_dss_3_1_cardholder_data_retention)
	msg := sprintf("PCI-DSS-3.1-cardholder-data-retention: attestation expired (expires_at=%s)", [input.pci_dss_3_1_cardholder_data_retention.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.pci_dss_3_1_cardholder_data_retention, 365)
	msg := sprintf("PCI-DSS-3.1-cardholder-data-retention: attestation not reviewed in 365 days (last_review_at=%s)", [input.pci_dss_3_1_cardholder_data_retention.last_review_at])
}

package concord.pci_dss.pci_dss_3_2_no_store_sensitive_authentication_data

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_3_2_no_store_sensitive_authentication_data")
	msg := "PCI-DSS-3.2-no-store-sensitive-authentication-data: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.pci_dss_3_2_no_store_sensitive_authentication_data)
	msg := sprintf("PCI-DSS-3.2-no-store-sensitive-authentication-data: attestation expired (expires_at=%s)", [input.pci_dss_3_2_no_store_sensitive_authentication_data.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.pci_dss_3_2_no_store_sensitive_authentication_data, 365)
	msg := sprintf("PCI-DSS-3.2-no-store-sensitive-authentication-data: attestation not reviewed in 365 days (last_review_at=%s)", [input.pci_dss_3_2_no_store_sensitive_authentication_data.last_review_at])
}

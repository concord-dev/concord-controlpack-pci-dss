package concord.pci_dss.pci_dss_8_5_no_shared_accounts

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_8_5_no_shared_accounts")
	msg := "PCI-DSS-8.5-no-shared-accounts: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.pci_dss_8_5_no_shared_accounts)
	msg := sprintf("PCI-DSS-8.5-no-shared-accounts: attestation expired (expires_at=%s)", [input.pci_dss_8_5_no_shared_accounts.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.pci_dss_8_5_no_shared_accounts, 365)
	msg := sprintf("PCI-DSS-8.5-no-shared-accounts: attestation not reviewed in 365 days (last_review_at=%s)", [input.pci_dss_8_5_no_shared_accounts.last_review_at])
}

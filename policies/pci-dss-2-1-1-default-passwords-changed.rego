package concord.pci_dss.pci_dss_2_1_1_default_passwords_changed

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_2_1_1_default_passwords_changed")
	msg := "PCI-DSS-2.1.1-default-passwords-changed: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.pci_dss_2_1_1_default_passwords_changed)
	msg := sprintf("PCI-DSS-2.1.1-default-passwords-changed: attestation expired (expires_at=%s)", [input.pci_dss_2_1_1_default_passwords_changed.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.pci_dss_2_1_1_default_passwords_changed, 365)
	msg := sprintf("PCI-DSS-2.1.1-default-passwords-changed: attestation not reviewed in 365 days (last_review_at=%s)", [input.pci_dss_2_1_1_default_passwords_changed.last_review_at])
}

package concord.pci_dss.pci_dss_2_2_1_system_configuration_standards

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_2_2_1_system_configuration_standards")
	msg := "PCI-DSS-2.2.1-system-configuration-standards: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.pci_dss_2_2_1_system_configuration_standards)
	msg := sprintf("PCI-DSS-2.2.1-system-configuration-standards: attestation expired (expires_at=%s)", [input.pci_dss_2_2_1_system_configuration_standards.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.pci_dss_2_2_1_system_configuration_standards, 365)
	msg := sprintf("PCI-DSS-2.2.1-system-configuration-standards: attestation not reviewed in 365 days (last_review_at=%s)", [input.pci_dss_2_2_1_system_configuration_standards.last_review_at])
}

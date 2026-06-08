package concord.pci_dss.pci_dss_11_2_internal_external_scans

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_11_2_internal_external_scans")
	msg := "PCI-DSS-11.2-internal-external-scans: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.pci_dss_11_2_internal_external_scans)
	msg := sprintf("PCI-DSS-11.2-internal-external-scans: attestation expired (expires_at=%s)", [input.pci_dss_11_2_internal_external_scans.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.pci_dss_11_2_internal_external_scans, 365)
	msg := sprintf("PCI-DSS-11.2-internal-external-scans: attestation not reviewed in 365 days (last_review_at=%s)", [input.pci_dss_11_2_internal_external_scans.last_review_at])
}

package concord.pci_dss.pci_dss_11_1_wireless_access_points

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_11_1_wireless_access_points")
	msg := "PCI-DSS-11.1-wireless-access-points: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.pci_dss_11_1_wireless_access_points)
	msg := sprintf("PCI-DSS-11.1-wireless-access-points: attestation expired (expires_at=%s)", [input.pci_dss_11_1_wireless_access_points.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.pci_dss_11_1_wireless_access_points, 365)
	msg := sprintf("PCI-DSS-11.1-wireless-access-points: attestation not reviewed in 365 days (last_review_at=%s)", [input.pci_dss_11_1_wireless_access_points.last_review_at])
}

package concord.pci_dss.pci_dss_10_6_log_review

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_10_6_log_review")
	msg := "PCI-DSS-10.6-log-review: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.pci_dss_10_6_log_review)
	msg := sprintf("PCI-DSS-10.6-log-review: attestation expired (expires_at=%s)", [input.pci_dss_10_6_log_review.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.pci_dss_10_6_log_review, 365)
	msg := sprintf("PCI-DSS-10.6-log-review: attestation not reviewed in 365 days (last_review_at=%s)", [input.pci_dss_10_6_log_review.last_review_at])
}

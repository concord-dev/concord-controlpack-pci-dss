package concord.pci_dss.pci_dss_12_3_acceptable_use_policy

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_12_3_acceptable_use_policy")
	msg := "PCI-DSS-12.3-acceptable-use-policy: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.pci_dss_12_3_acceptable_use_policy)
	msg := sprintf("PCI-DSS-12.3-acceptable-use-policy: attestation expired (expires_at=%s)", [input.pci_dss_12_3_acceptable_use_policy.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.pci_dss_12_3_acceptable_use_policy, 365)
	msg := sprintf("PCI-DSS-12.3-acceptable-use-policy: attestation not reviewed in 365 days (last_review_at=%s)", [input.pci_dss_12_3_acceptable_use_policy.last_review_at])
}

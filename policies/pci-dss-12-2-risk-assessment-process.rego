package concord.pci_dss.pci_dss_12_2_risk_assessment_process

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_12_2_risk_assessment_process")
	msg := "PCI-DSS-12.2-risk-assessment-process: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.pci_dss_12_2_risk_assessment_process)
	msg := sprintf("PCI-DSS-12.2-risk-assessment-process: attestation expired (expires_at=%s)", [input.pci_dss_12_2_risk_assessment_process.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.pci_dss_12_2_risk_assessment_process, 365)
	msg := sprintf("PCI-DSS-12.2-risk-assessment-process: attestation not reviewed in 365 days (last_review_at=%s)", [input.pci_dss_12_2_risk_assessment_process.last_review_at])
}

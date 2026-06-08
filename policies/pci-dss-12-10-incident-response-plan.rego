package concord.pci_dss.pci_dss_12_10_incident_response_plan

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_12_10_incident_response_plan")
	msg := "PCI-DSS-12.10-incident-response-plan: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.pci_dss_12_10_incident_response_plan)
	msg := sprintf("PCI-DSS-12.10-incident-response-plan: attestation expired (expires_at=%s)", [input.pci_dss_12_10_incident_response_plan.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.pci_dss_12_10_incident_response_plan, 365)
	msg := sprintf("PCI-DSS-12.10-incident-response-plan: attestation not reviewed in 365 days (last_review_at=%s)", [input.pci_dss_12_10_incident_response_plan.last_review_at])
}

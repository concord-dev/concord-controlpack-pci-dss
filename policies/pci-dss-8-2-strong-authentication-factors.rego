package concord.pci_dss.pci_dss_8_2_strong_authentication_factors

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_8_2_strong_authentication_factors")
	msg := "PCI-DSS-8.2-strong-authentication-factors: aws evidence missing"
}

deny contains msg if {
	some r in input.pci_dss_8_2_strong_authentication_factors.resources
	not r.compliant
	msg := sprintf("PCI-DSS-8.2-strong-authentication-factors: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

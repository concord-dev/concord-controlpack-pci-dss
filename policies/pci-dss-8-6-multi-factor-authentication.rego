package concord.pci_dss.pci_dss_8_6_multi_factor_authentication

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_8_6_multi_factor_authentication")
	msg := "PCI-DSS-8.6-multi-factor-authentication: aws evidence missing"
}

deny contains msg if {
	some r in input.pci_dss_8_6_multi_factor_authentication.resources
	not r.compliant
	msg := sprintf("PCI-DSS-8.6-multi-factor-authentication: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

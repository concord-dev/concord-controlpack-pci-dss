package concord.pci_dss.pci_dss_6_6_web_application_firewall

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_6_6_web_application_firewall")
	msg := "PCI-DSS-6.6-web-application-firewall: aws evidence missing"
}

deny contains msg if {
	some r in input.pci_dss_6_6_web_application_firewall.resources
	not r.compliant
	msg := sprintf("PCI-DSS-6.6-web-application-firewall: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

package concord.pci_dss.pci_dss_2_3_encrypt_non_console_admin

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "pci_dss_2_3_encrypt_non_console_admin")
	msg := "PCI-DSS-2.3-encrypt-non-console-admin: aws evidence missing"
}

deny contains msg if {
	some r in input.pci_dss_2_3_encrypt_non_console_admin.resources
	not r.compliant
	msg := sprintf("PCI-DSS-2.3-encrypt-non-console-admin: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

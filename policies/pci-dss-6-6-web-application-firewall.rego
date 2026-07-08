package concord.pci_dss.pci_dss_6_6_web_application_firewall

import rego.v1

# PCI DSS Requirement 6.6 / v4.0 6.4.1-6.4.2 — every public-facing web
# application must sit behind a WAF. Concord inventories public-facing web
# entry points (internet-facing ALBs, enabled CloudFront distributions) and
# requires each to have an associated WebACL. Fail-closed: a public resource
# is denied unless it explicitly reports web_acl_associated == true.

deny contains msg if {
	not input.waf_coverage
	msg := "no WAF-coverage evidence collected"
}

deny contains msg if {
	some resource in input.waf_coverage.resources
	resource.public_facing == true
	not resource.web_acl_associated == true
	msg := sprintf("public-facing %s %q has no associated WAF WebACL", [object.get(resource, "type", "web resource"), resource.arn])
}

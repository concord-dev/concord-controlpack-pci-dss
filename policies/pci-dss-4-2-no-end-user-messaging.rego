package concord.pci_dss.r_4_2

import rego.v1

# PCI DSS v4.0 Requirement 4.2.2 — PAN must never be sent via unprotected
# end-user messaging (email, SMS, chat), and a policy must prohibit it.
# Evidenced by a signed policy attestation collected from the repository via
# github/file_glob (frontmatter), so each matched file is in
# input.pan_messaging_policy.docs with its frontmatter keys plus a "path".

max_review_age_days := 365

nanos_per_day := 86400000000000

required_fields := ["policy_prohibits_pan_messaging", "channels_covered", "dlp_tooling", "last_reviewed_at", "signature_verified"]

# The channels the prohibition must explicitly cover.
required_channels := {"email", "sms", "chat"}

deny contains msg if {
	not input.pan_messaging_policy
	msg := "PCI DSS 4.2.2: no PAN end-user-messaging policy evidence collected"
}

deny contains msg if {
	input.pan_messaging_policy
	count(object.get(input.pan_messaging_policy, "docs", [])) == 0
	msg := "PCI DSS 4.2.2: no PAN end-user-messaging policy document found at the configured repository path"
}

deny contains msg if {
	some doc in input.pan_messaging_policy.docs
	some field in required_fields
	not has_value(doc, field)
	msg := sprintf("PCI DSS 4.2.2: policy %q is missing required field %q", [doc.path, field])
}

# The prohibition must be attested as an explicit boolean true.
deny contains msg if {
	some doc in input.pan_messaging_policy.docs
	has_value(doc, "policy_prohibits_pan_messaging")
	not doc.policy_prohibits_pan_messaging == true
	msg := sprintf("PCI DSS 4.2.2: policy %q does not affirm policy_prohibits_pan_messaging=true (got %v)", [doc.path, doc.policy_prohibits_pan_messaging])
}

# Every named messaging channel must be in scope.
deny contains msg if {
	some doc in input.pan_messaging_policy.docs
	has_value(doc, "channels_covered")
	some channel in required_channels
	not channel in {c | some c in doc.channels_covered}
	msg := sprintf("PCI DSS 4.2.2: policy %q does not cover the %q messaging channel", [doc.path, channel])
}

# Freshness: the policy must have been reviewed within the last year.
deny contains msg if {
	some doc in input.pan_messaging_policy.docs
	has_value(doc, "last_reviewed_at")
	reviewed_ns := time.parse_rfc3339_ns(doc.last_reviewed_at)
	cutoff_ns := time.now_ns() - (max_review_age_days * nanos_per_day)
	reviewed_ns < cutoff_ns
	msg := sprintf("PCI DSS 4.2.2: policy %q was last reviewed more than %d days ago (last_reviewed_at=%s)", [doc.path, max_review_age_days, doc.last_reviewed_at])
}

# Signature must be an explicit boolean true.
deny contains msg if {
	some doc in input.pan_messaging_policy.docs
	has_value(doc, "signature_verified")
	not doc.signature_verified == true
	msg := sprintf("PCI DSS 4.2.2: policy %q signature is not verified (signature_verified=%v)", [doc.path, doc.signature_verified])
}

has_value(doc, key) if {
	v := doc[key]
	not is_blank(v)
}

is_blank(v) if v == null

is_blank(v) if v == ""

is_blank(v) if {
	is_array(v)
	count(v) == 0
}

is_blank(v) if {
	is_object(v)
	count(v) == 0
}

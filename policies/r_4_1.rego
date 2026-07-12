package concord.pci_dss.r_4_1

import rego.v1

deny contains msg if {
    not input.bucket_policies
    msg := "no bucket-policy evidence collected"
}

deny contains msg if {
    some bucket in input.bucket_policies.buckets
    bucket.tags.pci == "true"
    not enforces_tls(bucket)
    msg := sprintf("PCI bucket %q does not enforce TLS via bucket policy", [bucket.name])
}

enforces_tls(bucket) if {
    some statement in bucket.policy.Statement
    statement.Effect == "Deny"
    statement.Condition.Bool["aws:SecureTransport"] == "false"
    statement.Action == "s3:*"
}

# doc 31 §4 — no fail-open tag gates: a resource with no 'pci' tag is neither confirmed in-scope
# nor out-of-scope, so every deny above skips it and it would pass silently.
# Warn on the unclassified resource instead of ignoring it.

warn contains msg if {
    some resource in input.bucket_policies.buckets
    not classified(resource)
    msg := sprintf("S3 bucket %q has no pci tag, so this control's checks did not apply to it — tag pci=true to bring it into cardholder-data (PCI) scope or pci=false to confirm it is out of scope", [resource.name])
}

classified(resource) if resource.tags.pci == "true"

classified(resource) if resource.tags.pci == "false"

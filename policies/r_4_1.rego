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

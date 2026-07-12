package concord.pci_dss.r_3_4

import rego.v1

deny contains msg if {
    not input.pci_encryption
    msg := "no PCI-encryption evidence collected"
}

deny contains msg if {
    some bucket in input.pci_encryption.buckets
    is_pci(bucket)
    not bucket.encryption.configured
    msg := sprintf("PCI bucket %q has no server-side encryption", [bucket.name])
}

deny contains msg if {
    some bucket in input.pci_encryption.buckets
    is_pci(bucket)
    bucket.encryption.configured
    some rule in bucket.encryption.rules
    rule.sse_algorithm == "AES256"
    msg := sprintf("PCI bucket %q uses AES256 — PCI requires customer-managed KMS keys", [bucket.name])
}

deny contains msg if {
    some rds in input.pci_encryption.rds_instances
    is_pci(rds)
    not rds.encryption.configured
    msg := sprintf("PCI RDS %q has no encryption-at-rest", [rds.identifier])
}

is_pci(resource) if {
    resource.tags.pci == "true"
}

# doc 31 §4 — no fail-open tag gates: a resource with no 'pci' tag is neither confirmed in-scope
# nor out-of-scope, so every deny above skips it and it would pass silently.
# Warn on the unclassified resource instead of ignoring it.

warn contains msg if {
    some resource in input.pci_encryption.buckets
    not classified(resource)
    msg := sprintf("S3 bucket %q has no pci tag, so this control's checks did not apply to it — tag pci=true to bring it into cardholder-data (PCI) scope or pci=false to confirm it is out of scope", [resource.name])
}

warn contains msg if {
    some resource in input.pci_encryption.rds_instances
    not classified(resource)
    msg := sprintf("RDS instance %q has no pci tag, so this control's checks did not apply to it — tag pci=true to bring it into cardholder-data (PCI) scope or pci=false to confirm it is out of scope", [resource.identifier])
}

classified(resource) if resource.tags.pci == "true"

classified(resource) if resource.tags.pci == "false"

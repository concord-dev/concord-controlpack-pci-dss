package concord.pci_dss.r_9_4

import rego.v1

required_fields := {"approval_date", "last_reviewed_at",
                    "destruction_method", "disposal_log"}

deny contains msg if {
    not input.attestation
    msg := "no media-handling attestation collected"
}

deny contains msg if {
    input.attestation.kind != "media_handling"
    msg := sprintf("attestation kind is %q, expected \"media_handling\"", [input.attestation.kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("attestation missing field: %s", [f])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "media-handling attestation signature did not verify"
}

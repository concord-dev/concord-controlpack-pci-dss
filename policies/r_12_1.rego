package concord.pci_dss.r_12_1

import rego.v1

required_fields := {"approval_date", "approving_authority",
                    "last_reviewed_at", "next_review_due"}

deny contains msg if {
    not input.attestation
    msg := "no policy attestation collected"
}

deny contains msg if {
    input.attestation.kind != "information_security_policy"
    msg := sprintf("attestation kind is %q, expected \"information_security_policy\"", [input.attestation.kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("policy attestation missing field: %s", [f])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "policy attestation signature did not verify"
}

deny contains msg if {
    review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
    review_due < time.now_ns()
    msg := "policy review is overdue"
}

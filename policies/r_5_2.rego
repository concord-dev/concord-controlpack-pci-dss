package concord.pci_dss.r_5_2

import rego.v1

deny contains msg if {
    not input.anti_malware
    msg := "no anti-malware evidence collected"
}

deny contains msg if {
    some region in input.anti_malware.active_regions
    not has_guardduty(region)
    msg := sprintf("GuardDuty disabled in region %q", [region])
}

deny contains msg if {
    not input.anti_malware.inspector_account_enabled
    msg := "AWS Inspector is not enabled at the account level"
}

has_guardduty(region) if {
    some d in input.anti_malware.guardduty_detectors
    d.region == region
    d.status == "ENABLED"
}

package concord.pci_dss.r_2_2

import rego.v1

deny contains msg if {
    not input.config_recorder
    msg := "no AWS Config evidence collected"
}

deny contains msg if {
    some region in input.config_recorder.active_regions
    not has_recording_in_region(region)
    msg := sprintf("Config recorder disabled in region %q", [region])
}

has_recording_in_region(region) if {
    some recorder in input.config_recorder.recorders
    recorder.region == region
    recorder.recording
}

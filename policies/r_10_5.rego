package concord.pci_dss.r_10_5

import rego.v1

min_retention := 365

deny contains msg if {
    not input.audit_trail
    msg := "no audit-trail evidence collected"
}

deny contains msg if {
    not has_multi_region_trail
    msg := "no multi-region CloudTrail trail is logging"
}

deny contains msg if {
    some trail in input.audit_trail.cloudtrail.trails
    trail.is_logging
    not trail.log_file_validation_enabled
    msg := sprintf("trail %q has log-file validation disabled", [trail.name])
}

deny contains msg if {
    some group in input.audit_trail.log_groups
    group.is_production
    not group.retention_in_days >= min_retention
    msg := sprintf("production log group %q retention %d days < %d", [group.name, group.retention_in_days, min_retention])
}

has_multi_region_trail if {
    some trail in input.audit_trail.cloudtrail.trails
    trail.is_multi_region_trail
    trail.is_logging
}

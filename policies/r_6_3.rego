package concord.pci_dss.r_6_3

import rego.v1

critical_sla := 7
high_sla := 30

deny contains msg if {
    not input.vuln_scan
    msg := "no vulnerability-scan evidence collected"
}

deny contains msg if {
    some issue in input.vuln_scan.issues
    issue.severity == "critical"
    issue.age_days > critical_sla
    msg := sprintf("CRITICAL vuln %q is %d days old (SLA %d)", [issue.id, issue.age_days, critical_sla])
}

deny contains msg if {
    some issue in input.vuln_scan.issues
    issue.severity == "high"
    issue.age_days > high_sla
    msg := sprintf("HIGH vuln %q is %d days old (SLA %d)", [issue.id, issue.age_days, high_sla])
}

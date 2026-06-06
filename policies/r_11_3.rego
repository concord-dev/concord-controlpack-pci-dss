package concord.pci_dss.r_11_3

import rego.v1

max_scan_age := 90

deny contains msg if {
    not input.vuln_scan
    msg := "no vulnerability-scan evidence collected"
}

deny contains msg if {
    input.vuln_scan.scan_age_days > max_scan_age
    msg := sprintf("most recent scan was %d days ago (max %d)", [input.vuln_scan.scan_age_days, max_scan_age])
}

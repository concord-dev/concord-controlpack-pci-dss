package concord.pci_dss.r_7_2

import rego.v1

max_admin_count := 5

deny contains msg if {
    not input.iam_admins
    msg := "no IAM privileged-principals evidence collected"
}

deny contains msg if {
    count(input.iam_admins.administrators) > max_admin_count
    msg := sprintf("%d admins (max %d)", [count(input.iam_admins.administrators), max_admin_count])
}

deny contains msg if {
    some admin in input.iam_admins.administrators
    admin.has_access_key
    msg := sprintf("admin %q holds a long-lived access key", [admin.username])
}

deny contains msg if {
    some admin in input.iam_admins.administrators
    not admin.mfa_enabled
    msg := sprintf("admin %q is not MFA-enrolled", [admin.username])
}

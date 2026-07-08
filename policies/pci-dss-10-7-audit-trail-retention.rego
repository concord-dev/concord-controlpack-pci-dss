package concord.pci_dss.r_10_7

import rego.v1

# PCI DSS Requirement 10.7 — retain audit-log history at least 12 months with
# the most recent 3 months immediately available. Concord checks CloudWatch log
# group retention and any S3 lifecycle rule used for log storage. Fail closed
# when no retention mechanism exists.

min_retention_days := 365

min_immediate_days := 90

deny contains msg if {
	not input.audit_retention
	msg := "no audit-log retention evidence collected"
}

deny contains msg if {
	input.audit_retention
	not has_retention_mechanism
	msg := "no audit-log retention mechanism configured (neither CloudWatch log-group retention nor an S3 lifecycle rule); failing closed (PCI DSS Requirement 10.7)"
}

deny contains msg if {
	some g in input.audit_retention.log_groups
	g.is_audit_log
	g.retention_in_days < min_retention_days
	msg := sprintf("audit log group %q retains logs for %d days, below the required %d days (PCI DSS Requirement 10.7)", [g.name, g.retention_in_days, min_retention_days])
}

deny contains msg if {
	lc := input.audit_retention.s3_lifecycle
	lc.expiration_days < min_retention_days
	msg := sprintf("S3 audit-log bucket %q expires objects after %d days, below the required %d days (PCI DSS Requirement 10.7)", [lc.bucket, lc.expiration_days, min_retention_days])
}

deny contains msg if {
	lc := input.audit_retention.s3_lifecycle
	lc.transition_to_archive_days < min_immediate_days
	msg := sprintf("S3 audit-log bucket %q archives objects to cold storage after %d days; at least %d days must remain immediately available (PCI DSS Requirement 10.7)", [lc.bucket, lc.transition_to_archive_days, min_immediate_days])
}

has_retention_mechanism if {
	count(input.audit_retention.log_groups) > 0
}

has_retention_mechanism if {
	input.audit_retention.s3_lifecycle
}

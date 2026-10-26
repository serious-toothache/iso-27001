# Evidence summary: run_20261026T151757Z

- **Account:** 111122223333 · **Regions:** af-south-1, eu-west-1 · **Source:** mock:mock_aws_environment.json
- **Collected:** 2026-10-26T15:17:57+00:00 · **As of:** 2026-10-23
- **Collector:** v2.0.0 · commit `not committed`
- **Result:** 2 pass · 7 fail · 0 error

| Check | Annex A | SOC 2 | Scope | Status | Summary | Evidence |
|---|---|---|---|---|---|---|
| IAM-01: IAM password policy meets baseline | A.5.17 | CC6.1 | global | ❌ FAIL | 3 password policy setting(s) below baseline. | [`IAM-01.json`](IAM-01.json) |
| IAM-02: Root user has MFA enabled | A.8.2, A.8.5 | CC6.1 | global | ✅ PASS | Root MFA is enabled. | [`IAM-02.json`](IAM-02.json) |
| IAM-03: All console users have MFA | A.8.5 | CC6.1 | global | ❌ FAIL | 2 of 5 console user(s) have no MFA. | [`IAM-03.json`](IAM-03.json) |
| IAM-04: Active access keys rotated within 90 days | A.5.17 | CC6.1 | global | ❌ FAIL | 1 of 3 active access key(s) exceed 90 days. | [`IAM-04.json`](IAM-04.json) |
| LOG-01: Multi-region CloudTrail with log file validation | A.8.15 | CC7.2 | global | ❌ FAIL | No trail is multi-region, logging and integrity-validated. | [`LOG-01.json`](LOG-01.json) |
| S3-01: S3 Block Public Access enabled at account level | A.8.3 | CC6.1, C1.1 | global | ✅ PASS | All four account-level Block Public Access settings are on. | [`S3-01.json`](S3-01.json) |
| CRY-01: EBS encryption by default enabled | A.8.24 | CC6.1, C1.1 | regional | ❌ FAIL | EBS encryption by default is off in 1 of 2 region(s). | [`CRY-01.json`](CRY-01.json) |
| NET-01: No security group exposes SSH/RDP to the internet | A.8.20 | CC6.6 | regional | ❌ FAIL | 1 internet-exposed admin port rule(s) across 2 region(s). | [`NET-01.json`](NET-01.json) |
| MON-01: GuardDuty threat detection enabled | A.8.16 | CC7.2 | regional | ❌ FAIL | GuardDuty is not enabled in 2 of 2 region(s). | [`MON-01.json`](MON-01.json) |

Integrity: each file's SHA-256 is recorded in [`manifest.json`](manifest.json). Run `python collect_evidence.py --verify <run folder>` to detect tampering.

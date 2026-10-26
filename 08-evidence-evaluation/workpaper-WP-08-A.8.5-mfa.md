# Workpaper WP-08: A.8.5 Secure authentication (console MFA)

A worked example of the modern workpaper format: a precise population, a reproducible test, period-wide evidence for the conclusion, and AI use disclosed.

| | |
|---|---|
| **Client** | Tausi Telehealth Ltd (fictional) |
| **Control** | ISO/IEC 27001:2022 A.8.5 Secure authentication · related A.5.17, A.8.2 |
| **SOC 2 crosswalk** | CC6.1 |
| **Period** | Design as of 23 Oct 2026. Operation 1 Jul – 30 Sep 2026 |
| **Control statement (client)** | "MFA is required for every IAM user with console access." (Mapping row A.8.5, [`01-control-mapping`](../01-control-mapping/annex-a-control-mapping.csv)) |
| **Prepared by** | Louisz Rigensky W. · AI use: [AI-06](ai-use-log.md) |

## Control objective

Nobody can sign in to the AWS console with a password alone.

## Test procedure

1. **Re-performance (design).** Run the evidence collector against the read-only audit role and evaluate the IAM credential report: every user with `password_enabled = true` must have `mfa_active = true`.
2. **Inspection (operation).** Read the daily AWS Config results for `mfa-enabled-for-iam-console-access` across Q3.
3. **Inspection (operation).** Query CloudTrail for `ConsoleLogin` events with `MFAUsed = No` in Q3.

## Population

> All IAM users in account `111122223333` with a console password, as listed in the IAM credential report retrieved by `collect_evidence.py` v2.0.0 (run `run_20261026T151757Z`, re-run 26 Oct 2026 with `--as-of 2026-10-23`), excluding `<root_account>` (tested separately in IAM-02), **n = 5**.

IAM is a global service, so one report covers both in-scope regions.

## Sample

> **100% of the population (5 of 5).** The credential report is a complete system export, so no sampling is needed. Re-performable with:
> `python collect_evidence.py --mock sample_data/mock_aws_environment.json --as-of 2026-10-23`

## Evidence

| Evidence | Source | Integrity |
|---|---|---|
| [`IAM-03.json`](../02-evidence-collection/example-output/run_20261026T151757Z/IAM-03.json) | `iam:GenerateCredentialReport`, `iam:GetCredentialReport` | File SHA-256 `bddd2b80dbdc8de0d5be5d7bae642527e69f50b30eabd8623b7a64c34ffafe86` (manifest). Raw-data SHA-256 `4f46d01ec77e8f51d0fb1f382f849eac581d0edf65560496678be238e61cc73f`. `--verify`: intact |
| [`config-rule-evaluations-q3.csv`](../07-continuous-monitoring/evidence/config-rule-evaluations-q3.csv) | AWS Config compliance history | SHA-256 `d1cb18df29b55b3b3381fb0208ac02d0cda88fd4e979e7936fe6d64222ce4783` |
| [`cloudtrail-sample-q3.json`](../07-continuous-monitoring/evidence/cloudtrail-sample-q3.json) | CloudTrail Lake, `eventName = ConsoleLogin` | SHA-256 `a33ef1163faff3b81a8f9753cacd6e4ff1440c5d3f98b73e0b5b1d86f21d58a7`. Tier 2 only: log file validation is off (GAP-06) |

## Results

| User | Console | MFA | Result |
|---|---|---|---|
| amina.otieno | ✅ | ✅ | Pass |
| brian.kamau | ✅ | ✅ | Pass |
| carol.wanjiru | ✅ | ❌ | **Exception** |
| david.mutua | ✅ | ✅ | Pass |
| contractor-devops | ✅ | ❌ | **Exception** (external contractor) |

**Across the period:** `mfa-enabled-for-iam-console-access` reported **2 NON_COMPLIANT resources on all 86 days it ran** between 2026-07-01 and 2026-09-30 (no data 14–19 Aug, recorder stopped). The same two users. The alert was raised on 1 Jul and never ticketed (WP-07, DRF-02/03).

**In use:** `contractor-devops` signed in to the console with `MFAUsed: No` at 2026-09-02T07:40:51Z from 198.51.100.77. Four minutes later the same session opened SSH to the internet on the production app servers (WP-07 §4.3).

## Conclusion

**Exception noted. The control is not designed or operating effectively.** 2 of 5 console users (40%) can sign in with a password alone, including an external contractor. AWS Config shows the condition held on every evaluated day of Q3, and CloudTrail shows a password-only sign-in followed by a high-risk change. → **GAP-01** (Critical).

How the test would have surfaced exceptions: any console user with `mfa_active = false` in the credential report, any day with a non-zero NON_COMPLIANT count for the Config rule, or any `ConsoleLogin` with `MFAUsed = No`.

**Not covered here:** GitHub org 2FA enforcement (mapping row A.8.5, GitHub column). Requested as part of R6 but not yet tested.

## Workpaper anti-patterns avoided

| Not written | Written instead |
|---|---|
| "Evidence provided by management" | The exact API calls, run ID and file hashes |
| "Reviewed screenshots of IAM users" | A credential report re-performed by the auditor |
| "No exceptions noted" for the period | A day-by-day Config result across the period, and how an exception would have shown up |

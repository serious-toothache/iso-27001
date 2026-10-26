# Workpaper WP-07: Continuous configuration monitoring and drift response

| | |
|---|---|
| **Client** | Tausi Telehealth Ltd (fictional) |
| **Controls** | ISO/IEC 27001:2022 A.8.9 Configuration management · A.8.16 Monitoring activities · A.8.20 Networks security · A.8.5 Secure authentication · A.5.23 Information security for use of cloud services |
| **SOC 2 crosswalk** | CC7.1 · CC7.2 · CC4.1 · CC6.6 |
| **Period** | 1 July – 30 September 2026 (Q3), open items aged to 23 October 2026 |
| **System** | AWS Config conformance pack (3 rules) in account `111122223333`, EventBridge rule `config-noncompliant-to-pagerduty`, ticketing in Jira (TT-*) |
| **Prepared by** | Louisz Rigensky W. · 23 Oct 2026 · AI use logged in [AI-05](../08-evidence-evaluation/ai-use-log.md) |

## 1. Control objective

Insecure configuration is detected automatically every day, alerted, ticketed and fixed within SLA (high: 7 days, medium: 30 days). The detection itself runs without interruption in every in-scope region.

## 2. The three-evidence stack

A dashboard screenshot from today saying "compliant" proves nothing about Q3. The evidence is:

| Layer | What it proves | Evidence |
|---|---|---|
| 1. Configuration | What the rules check, how often, which regions, where alerts go | [`config-recorder-status.json`](evidence/config-recorder-status.json) |
| 2. Execution log | The rules ran every day of the period, or didn't | [`config-rule-evaluations-q3.csv`](evidence/config-rule-evaluations-q3.csv) (daily results, 3 rules) |
| 3. Alerts + resolution | What happened after each failure | [`drift-events-q3.csv`](evidence/drift-events-q3.csv), joined to Jira tickets |
| Supporting | Who changed what (5 Ws) | [`cloudtrail-sample-q3.json`](evidence/cloudtrail-sample-q3.json) |

## 3. Population and sampling

| What | Strategy | Size | Why |
|---|---|---|---|
| Daily rule executions | **Continuous operation**, full period | 92 days × 3 rules | Any gap means the control was off. A 1-week-per-quarter temporal sample would have a 1 in 13 chance of hitting a 6-day gap |
| Output quality | Sample of executions | 3 days (09 Jul, 21 Aug, 24 Sep), re-performed by comparing each day's NON_COMPLIANT resources to the drift log | A few executions are enough to show the rule reports the right thing |
| Drift events | **Anomaly**, all | 6 of 6 | Alerts are few by definition and high-risk. Review every one |
| Changes to the monitoring itself | **Event-type**, all | `StopConfigurationRecorder`, `StartConfigurationRecorder` | Privileged operations that switch the evidence generator off |
| Regions | All in-scope | af-south-1, eu-west-1 | Config is a regional service |

## 4. Results

Re-performed with [`analyze_continuous.py`](analyze_continuous.py).

### 4.1 Configuration

| Check | Result |
|---|---|
| Recorder running in af-south-1 | ✅ Recording, last status SUCCESS |
| Recorder running in eu-west-1 (DR region) | ❌ **No configuration recorder exists.** The patient-data copy in `tausi-dr-restore-test` ([WP-05](../05-iac-audit/workpaper-WP-05-s3-module.md)) was never evaluated |
| Alerts routed for every rule | ❌ The EventBridge pattern lists only `restricted-ssh` and `mfa-enabled-for-iam-console-access`. **`s3-bucket-versioning-enabled` failures go nowhere** |

### 4.2 Execution log

```
mfa-enabled-for-iam-console-access     ran 86/92 days  GAP 2026-08-14 to 2026-08-19 (6 days)
restricted-ssh                         ran 86/92 days  GAP 2026-08-14 to 2026-08-19 (6 days)
s3-bucket-versioning-enabled           ran 86/92 days  GAP 2026-08-14 to 2026-08-19 (6 days)
```

All three rules stop on the same day, so the cause is upstream of the rules. CloudTrail (event-type sample) shows why:

| Who | What | When (UTC) | Where | How |
|---|---|---|---|---|
| `contractor-devops` | `StopConfigurationRecorder` | 2026-08-14 07:58:12 | 198.51.100.77 / af-south-1 | AWS CLI, long-lived key `AKIAIOSFODNN7EXAMPLE` (215 days old, [IAM-04](../02-evidence-collection/example-output/run_20261026T151757Z/IAM-04.json)) |
| `brian.kamau` | `StartConfigurationRecorder` | 2026-08-20 08:31:45 | 196.201.214.10 / af-south-1 | Console |

No alert fired on `StopConfigurationRecorder`. The monitoring had no monitor of its own for 6 days. Nobody has given a reason for the stop (open request R9).

### 4.3 Drift workflow: Detect → Alert → Ticket → Remediate → Validate

| ID | Rule | Resource | Status | Detail |
|---|---|---|---|---|
| DRF-01 | restricted-ssh | `staging-debug` SG | ✅ ok | TT-301, fixed in 21.7 h, validated |
| DRF-02 | mfa-enabled-for-iam-console-access | `carol.wanjiru` | ❌ **broken response** | Alerted 1 Jul, never ticketed. Still open (113 days) |
| DRF-03 | mfa-enabled-for-iam-console-access | `contractor-devops` | ❌ **broken response** | Alerted 1 Jul, never ticketed. Still open (113 days) |
| DRF-04 | s3-bucket-versioning-enabled | `tausi-tmp-export-carol` | ❌ **broken alert** | Detected 21 Aug, never alerted (routing gap, 4.1) |
| DRF-05 | restricted-ssh | `app-servers` SG, SSH from 0.0.0.0/0 | ❌ **broken remediation** | TT-412 opened 3 Sep, open 50 days vs 7-day SLA. This is [GAP-03](../03-gap-assessment/README.md#4-findings) |
| DRF-06 | restricted-ssh | `temp-vendor-access` SG | ✅ ok | TT-430, fixed in 21.2 h, validated |

**MTTR for remediated drift: 21.4 h** (2 events). That number looks good only because it leaves out the 4 events that were never remediated. Reported together: **2 of 6 drift events (33%) were resolved.**

DRF-05 traced with the 5 Ws: `contractor-devops` signed in to the console **without MFA** at 07:40:51 on 2 Sep from 198.51.100.77, then added `tcp/22 from 0.0.0.0/0` to `sg-0a1b2c3d4e5f60002` at 07:44:03 with the description "debug - remove later". No change record exists (inquiry).

### 4.4 Output quality (3 sampled days)

On each sampled day, the NON_COMPLIANT count in the execution log matched the open drift events for that rule: 9 Jul restricted-ssh 1 (DRF-01), 21 Aug versioning 1 (DRF-04), 24 Sep restricted-ssh 2 (DRF-05, DRF-06). ✅ The rules report correctly when they run.

## 5. Conclusion

**Exceptions noted. The control did not operate effectively for Q3.**

The rules are accurate when they run, and the two drift events that reached a ticket were fixed within a day. But every other link fails at least once: detection was off for 6 of 92 days (7%) after a contractor stopped the recorder unnoticed, detection never covered the DR region, one rule's alerts go nowhere, two MFA alerts have been ignored for the whole period, and the SSH exposure behind GAP-03 is 43 days past SLA. → **GAP-18**, plus eu-west-1 coverage in **GAP-19**.

The test would have surfaced exceptions as: any day without an evaluation for any rule, any in-scope region without a recorder, any rule not covered by alert routing, and any drift event without an alert, without a ticket, or past SLA.

## 6. Evidence index

| File | SHA-256 |
|---|---|
| `evidence/config-recorder-status.json` | `aebc7f76fb9bcfaf6051a89251e8a495a6d8ecacd0ae8c4a8bdadf0372d8ce3e` |
| `evidence/config-rule-evaluations-q3.csv` | `d1cb18df29b55b3b3381fb0208ac02d0cda88fd4e979e7936fe6d64222ce4783` |
| `evidence/drift-events-q3.csv` | `152cb1cbaa515f7fdb88468deaf254c06155ae7fa589c2f839f9af1ed10697d3` |
| `evidence/cloudtrail-sample-q3.json` | `a33ef1163faff3b81a8f9753cacd6e4ff1440c5d3f98b73e0b5b1d86f21d58a7` |

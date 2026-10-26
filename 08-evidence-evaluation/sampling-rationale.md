# Sampling Rationale

The question isn't "how big should the sample be?" It's **"what slice of the population gives enough confidence?"** Reviewers will ask four things of every test: the strategy and why, the slice and why, the size and its rationale, and any standard that applies. This page answers them for every test in the engagement.

No sampling standard is mandated for an ISO 27001 readiness assessment, and AICPA doesn't prescribe ITGC sample sizes for SOC 2. So the rationale is the defence, and it's written down.

| Test | Population | Strategy | Slice | Size | Rationale |
|---|---|---|---|---|---|
| Console MFA (IAM-03, [WP-08](workpaper-WP-08-A.8.5-mfa.md)) | IAM users with a console password | **Entire population** | All | 5 of 5 | The credential report lists every user. Testing all costs nothing extra |
| Access key age (IAM-04) | Active access keys | Entire population | All | 3 of 3 | Same |
| Regional settings (CRY-01, NET-01, MON-01) | In-scope regions | **Entity** | Every region | 2 of 2 | A regional service must be tested in every in-scope region |
| Patient-data bucket module ([WP-05](../05-iac-audit/workpaper-WP-05-s3-module.md)) | Buckets built from `s3-patient-data` | **n = 1 (module)** | The module at commit `3f9c2a17`, plus 3 of 3 callers' inputs | 1 | *"Module `s3-patient-data` is the single source of truth for patient-data buckets. All 3 instances are created from it with identical control attributes. Testing the module (n = 1) provides coverage of the full population."* Callers were read because one input varies |
| Orphan buckets (WP-05) | Buckets in the cloud but in no state | **All** | All | 2 of 2 | Orphans are the high-risk population |
| PR rules ([WP-06](../06-pipeline-audit/workpaper-WP-06-change-management.md)) | PRs merged to `main`, Q3 | **Event-type, all** | All | 39 of 39 | Structured API data. "All if feasible", and it was |
| Deploy trace (WP-06) | Production deploys, Q3 | Event-type, all | All | 39 of 39 | Same |
| Protection bypasses (WP-06) | `protected_branch` audit events | **Anomaly, all** | All | 4 of 4 | Few by definition and high-risk |
| Config executions ([WP-07](../07-continuous-monitoring/workpaper-WP-07-continuous-controls.md)) | Daily evaluations × 3 rules, Q3 | **Continuous operation** | Every day | 92 days | A gap on any day is a failure. A 1-week-per-quarter temporal sample would likely miss a 6-day gap |
| Config output quality (WP-07) | Daily evaluations | **Temporal** | 9 Jul, 21 Aug, 24 Sep (one per month, each with drift) | 3 | Enough to show the rule reports correctly. Picking days with drift tests the harder case |
| Drift events (WP-07) | Drift events, Q3 | **Anomaly, all** | All | 6 of 6 | Review every alert with its resolution |
| Monitoring changes (WP-07) | `Stop/StartConfigurationRecorder` events | Event-type, all | All | 2 of 2 | Privileged operations on the evidence generator itself |
| Log integrity (A.8.15 narrative, [04](../04-control-narrative/A.8.15-logging.md)) | Days in the period | Temporal | 5 random days | 5 | Planned for after GAP-06 is fixed. Validation is off today |

**Most tests here are 100% population, not samples.** That's the point of cloud-native evidence: once the population is an API export, testing all of it is cheaper than defending a sample.

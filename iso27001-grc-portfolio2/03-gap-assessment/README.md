# 03 · Gap Assessment and Risk Report: Tausi Telehealth Ltd vs ISO/IEC 27001:2022

**Files:** this report · [`gap-register.csv`](gap-register.csv) (full register with remediation, owners and effort; GitHub renders it as a table)

> Tausi Telehealth is a **fictional** Nairobi-based telehealth startup created for this portfolio. Technical findings come from the scripts and evidence in folders 02 and 05–07. ISMS findings come from simulated interviews and document requests. All names, accounts and IPs are invented or use AWS documentation examples.

## 1. Executive summary

Tausi Telehealth wants ISO/IEC 27001:2022 certification within 9 months to win a contract with a regional insurer. It handles patient health data on AWS.

**Tausi is not ready for certification today.** I identified **19 gaps: 2 Critical, 11 High and 6 Medium.**

The most urgent: a **HIGH SQL injection in patient search has been in production since 14 September**, because a contractor's pipeline change removed the security gate two weeks earlier (GAP-15). And **2 of 5 console users, one of them that same contractor, can sign in without MFA** (GAP-01). CloudTrail shows that contractor signing in with a password only and opening SSH to the internet four minutes later.

Three kinds of problems need three kinds of fixes:

- **Identity is the breach path.** No MFA (GAP-01), a 215-day-old contractor key (GAP-08) and weak passwords (GAP-10). The same contractor identity shows up in five other findings.
- **Controls exist but can be bypassed.** The Terraform module is good, but buckets get made by hand (GAP-13). Branch protection exists, but admins skip it and one person can write, merge and release a change (GAP-16). Monitoring exists, but it was switched off for 6 days and most alerts go nowhere (GAP-18).
- **The ISMS itself is missing.** No risk methodology, no Statement of Applicability, no internal audit (GAP-02, GAP-04, GAP-05). These would be major nonconformities at Stage 1, however good the technical controls are.

The good news: most technical gaps are **low effort** (configuration measured in hours), the standard S3 module enforces encryption, versioning and public-access blocking correctly, and root MFA and account-level S3 Block Public Access already pass.

## 2. Scope and method

| | |
|---|---|
| **Scope** | AWS production account `111122223333` in af-south-1 and eu-west-1; GitHub repo `tausi/tausi-platform`; ISMS documentation; Clauses 4–10 and a risk-based sample of Annex A ([scope memo](../00-engagement-scope/scope-memo.md)) |
| **Standard** | ISO/IEC 27001:2022, with a SOC 2 TSC crosswalk |
| **Assessment date** | 23 October 2026. Operating effectiveness look-back: Q3 (1 Jul – 30 Sep 2026) |
| **Configuration testing** | 9 automated checks, 100% population, both regions. Evidence run [`run_20261026T151757Z`](../02-evidence-collection/example-output/run_20261026T151757Z/summary.md) (collector v2.0.0, re-run 26 Oct with `--as-of 2026-10-23`) |
| **IaC testing** | Module read + orphan diff ([WP-05](../05-iac-audit/workpaper-WP-05-s3-module.md)) |
| **Pipeline testing** | 100% of 39 PRs and 39 deploys ([WP-06](../06-pipeline-audit/workpaper-WP-06-change-management.md)) |
| **Continuous controls** | 92 days of Config results, all drift events ([WP-07](../07-continuous-monitoring/workpaper-WP-07-continuous-controls.md)) |
| **ISMS testing** | Simulated interviews (CTO, Head of Engineering) and document requests |

Every technical finding cites a hashed evidence file. No finding relies on a screenshot. Evidence quality is assessed in [08](../08-evidence-evaluation/evidence-quality-assessment.md).

## 3. Rating method

`Risk score = Likelihood (1–5) × Impact (1–5)`

| Score | Rating | Expected response |
|---|---|---|
| 20–25 | Critical | Fix within 30 days; report to leadership now |
| 12–19 | High | Fix within 30–60 days |
| 6–11 | Medium | Fix within 90 days |
| 1–5 | Low | Accept or fix opportunistically |

Impact is weighted up for anything touching patient health data. Separately, a **certification blocker** flag marks clause-level gaps that would stop certification even if the security risk is moderate. A gap can be low-risk and still block the certificate. The ratings are my judgement and open to challenge.

## 4. Findings

| ID | Requirement | SOC 2 | Finding | Evidence | Score | Rating | Blocker |
|---|---|---|---|---|---|---|---|
| GAP-01 | A.8.5 | CC6.1 | 2 of 5 console users have no MFA, including a contractor | [IAM-03](../02-evidence-collection/example-output/run_20261026T151757Z/IAM-03.json), [WP-08](../08-evidence-evaluation/workpaper-WP-08-A.8.5-mfa.md) | 20 | 🔴 Critical | |
| GAP-15 | A.8.29, A.8.8 | CC8.1, CC7.1 | Security gate removed via the pipeline. HIGH SQL injection deployed to patient search | [WP-06](../06-pipeline-audit/workpaper-WP-06-change-management.md) | 20 | 🔴 Critical | |
| GAP-02 | Cl. 6.1.2 | CC3.2 | No documented risk assessment process or acceptance criteria | Interview, DR-03 | 16 | 🟠 High | ⛔ |
| GAP-03 | A.8.20 | CC6.6 | SSH open to the internet on production app servers. Ticket 43 days past SLA | [NET-01](../02-evidence-collection/example-output/run_20261026T151757Z/NET-01.json), [WP-07](../07-continuous-monitoring/workpaper-WP-07-continuous-controls.md) | 16 | 🟠 High | |
| GAP-16 | A.5.3, A.8.32 | CC8.1 | SoD bypassed: admins exempt, self-approved deploys, 4 of 39 PRs without a second human | [WP-06](../06-pipeline-audit/workpaper-WP-06-change-management.md) | 16 | 🟠 High | |
| GAP-04 | Cl. 6.1.3 d) | CC3.2 | No Statement of Applicability | DR-04 | 15 | 🟠 High | ⛔ |
| GAP-05 | Cl. 9.2 | CC4.1 | No internal audit programme | Interview | 15 | 🟠 High | ⛔ |
| GAP-06 | A.8.15 | CC7.2 | CloudTrail single-region, no log file validation | [LOG-01](../02-evidence-collection/example-output/run_20261026T151757Z/LOG-01.json) | 12 | 🟠 High | |
| GAP-07 | A.8.16 | CC7.2 | GuardDuty off in both regions | [MON-01](../02-evidence-collection/example-output/run_20261026T151757Z/MON-01.json) | 12 | 🟠 High | |
| GAP-08 | A.5.17 | CC6.1 | Contractor access key 215 days old, used for out-of-band changes | [IAM-04](../02-evidence-collection/example-output/run_20261026T151757Z/IAM-04.json) | 12 | 🟠 High | |
| GAP-09 | A.5.24 | CC7.3 | Incident response plan never approved or tested | IR-Plan-v0.3 | 12 | 🟠 High | |
| GAP-13 | A.8.9, A.5.9 | CC8.1 | 2 hand-made patient-data buckets outside Terraform | [WP-05](../05-iac-audit/workpaper-WP-05-s3-module.md) | 12 | 🟠 High | |
| GAP-18 | A.8.16, A.8.9 | CC7.2 | Monitoring off 6 days unnoticed; 4 of 6 drift events unresolved | [WP-07](../07-continuous-monitoring/workpaper-WP-07-continuous-controls.md) | 12 | 🟠 High | |
| GAP-10 | A.5.17 | CC6.1 | Password policy below baseline | [IAM-01](../02-evidence-collection/example-output/run_20261026T151757Z/IAM-01.json) | 9 | 🟡 Medium | |
| GAP-11 | A.5.18 | CC6.2 | No periodic access reviews | Interview | 9 | 🟡 Medium | |
| GAP-12 | A.5.19 | CC9.2 | Suppliers processing patient data never assessed | Supplier list | 9 | 🟡 Medium | |
| GAP-14 | A.8.15 | CC7.2 | Module makes access logging optional; uploads bucket turns it off | [WP-05](../05-iac-audit/workpaper-WP-05-s3-module.md) | 9 | 🟡 Medium | |
| GAP-17 | A.8.15, A.8.32 | CC7.2 | Build logs kept 90 days; 12 of 39 deploys can't be evidenced | [WP-06](../06-pipeline-audit/workpaper-WP-06-change-management.md) | 9 | 🟡 Medium | |
| GAP-19 | A.8.24, A.5.23 | CC6.1 | DR region eu-west-1 outside the baseline (EBS encryption, Config, GuardDuty) | [CRY-01](../02-evidence-collection/example-output/run_20261026T151757Z/CRY-01.json) | 8 | 🟡 Medium | |

Remediation actions, owners and effort for each gap are in [`gap-register.csv`](gap-register.csv).

## 5. Critical findings in detail

Causes are hypotheses to confirm with management.

### GAP-15. Security gate removed; HIGH SQL injection deployed to patient search

**Condition.** On 29 Aug 2026, PR #258 by contractor `kip-devops` added `continue-on-error: true` to the Semgrep job and removed it from `deploy-prod.needs` (`deploy.yml:28, 35`). It was approved by a software engineer, because CODEOWNERS has no owner for `.github/`. On 14 Sep, run 5248 (PR #264) reported a HIGH SQL injection at `app/patients/search.ts:41`. The job exited 1, was marked success, and the change deployed (`build-log-run-5248.txt:9-12, 16`).
**Criteria.** A.8.29 requires security testing in development and acceptance. A.8.8 requires known vulnerabilities to be addressed. SOC 2 CC8.1 and CC7.1.
**Cause (to confirm).** Scan flakiness was solved by turning the gate off. Pipeline files have no owner review.
**Effect.** A query that may let an attacker read the patient table is live in the patient-facing API. Exploitability is open request R12.

### GAP-01. Console users without MFA

**Condition.** `carol.wanjiru` and `contractor-devops` have console passwords and no MFA (`IAM-03.json`). AWS Config reported both as NON_COMPLIANT on every evaluated day of Q3. On 2 Sep at 07:40 UTC `contractor-devops` signed in with `MFAUsed: No` and at 07:44 opened SSH to the internet (`cloudtrail-sample-q3.json`).
**Criteria.** A.8.5 requires secure authentication. Tausi's own access standard requires MFA for all console users. SOC 2 CC6.1.
**Cause (to confirm).** IAM users are created by hand, with no policy denying actions without MFA. The Config alert was never ticketed (WP-07 DRF-02/03).
**Effect.** A guessed or phished password gives direct console access to the account holding patient data. It has already been followed by a high-risk change.

## 6. How the findings connect

One contractor identity, with no MFA and a stale key, runs through six findings. All times UTC.

| Date | Event | Gaps | Source |
|---|---|---|---|
| 21 Mar | `contractor-devops` access key last rotated | GAP-08 | IAM-04 |
| 1 Jul | Config flags two console users without MFA. Alert sent, never ticketed | GAP-01, GAP-18 | drift-events-q3.csv |
| 18 Jul | `brian.kamau` attaches an inline `s3:*` on `*` policy to `contractor-devops` | GAP-08 | cloudtrail-sample-q3.json |
| 12 Aug | Required approvals lowered to 0 for 3 h 33 min. PR #241 merged and self-approved for prod | GAP-16 | org audit log |
| 14 Aug | `contractor-devops` stops the AWS Config recorder with the stale key. No alert | GAP-18, GAP-08 | cloudtrail-sample-q3.json |
| 21 Aug | `carol.wanjiru` creates `tausi-tmp-export-carol` in the console. Detected, never alerted | GAP-13, GAP-18 | WP-05, WP-07 |
| 29 Aug | `kip-devops` turns off the Semgrep gate (PR #258) | GAP-15 | deploy.yml |
| 2 Sep | `contractor-devops` signs in without MFA and opens SSH to the internet | GAP-01, GAP-03 | cloudtrail-sample-q3.json |
| 10 Sep | `contractor-devops` creates `tausi-dr-restore-test` in eu-west-1 with the stale key | GAP-13, GAP-19 | WP-05 |
| 14 Sep | HIGH SQL injection deployed (PR #264) | GAP-15 | build-log-run-5248.txt |

Nothing here proves malicious intent. It does show that the contractor's access is broader, older and less monitored than anyone else's, and that the controls meant to catch it each failed once.

## 7. Reviewed and not flagged

These meet the requirement and are left out of the findings on purpose.

| Item | Why it passes | Source |
|---|---|---|
| Root user MFA, no root keys | MFA on, root not used for API work | IAM-02 |
| S3 Block Public Access | All four settings on at account level | S3-01 |
| Module encryption, rotation, versioning, public-access block, TLS-only, tags | Hard-coded, not variables. Live config matches the code | WP-05 §5.1, §5.4 |
| Module validation blocks | Patient data can't be deployed as `internal` or with a non-standard name | `variables.tf:5-8, 15-18` |
| State backend | Remote, KMS-encrypted, versioned, write access limited to 2 roles | WP-05 §5.3 |
| Force push and branch deletion on `main` | Blocked | `branch-protection-main.json` |
| Deploy commit integrity | All 39 deploys ship the PR's merge commit | WP-06 T1 |
| Drift response when ticketed | DRF-01 and DRF-06 fixed in under 22 h and validated | WP-07 |
| Web load balancer on 443 from 0.0.0.0/0 | Public HTTPS is the intended service | NET-01 raw data |
| No password expiry | Consistent with NIST SP 800-63B | IAM-01 raw data |

## 8. Evidence limitations and open requests

- **Synthetic data.** The environment and ISMS are simulated. Findings illustrate method, not a real company.
- **CloudTrail is not tamper-evident** while log file validation is off (GAP-06). CloudTrail-based facts are corroborated by a second source in each workpaper.
- **12 deploys are unevidenced** past GitHub's 90-day log retention (GAP-17).
- **Monitoring gap.** Config data excludes 14–19 Aug.
- **Point-in-time configuration.** Collector results show design on 23 Oct. Operation is covered for MFA, SSH, versioning and change management only.

Open requests ([full list](../00-engagement-scope/evidence-request-list.md)): **R9** reason for the recorder stop · **R10** change record for the 2 Sep SG change · **R11** risk acceptance for ENG-212 · **R12** exploitability of the #264 finding (urgent) · **R13** dev account data check · **R14** legal basis for patient data in eu-west-1.

## 9. Remediation roadmap

Sequenced by risk first, then by what certification needs and when.

**This week: contain**
- Confirm and fix or roll back the SQL injection from PR #264; restore Semgrep as a blocking, required check (GAP-15)
- Enforce MFA for all console users; deactivate the contractor's access key and review all its activity since March (GAP-01, GAP-08)
- Remove public SSH from `app-servers` and close TT-412 (GAP-03)

**Days 0–30: close the bypasses and start the ISMS core**
- Enforce branch protection for admins, require code-owner review with `.github/` owned by platform, prevent self-approval on production (GAP-16)
- Bring both orphan buckets under Terraform or delete them; deny `s3:CreateBucket` outside the pipeline role (GAP-13); hard-code access logging in the module (GAP-14)
- Enable GuardDuty, a multi-region validated CloudTrail, alerting on recorder stops and routing for every Config rule (GAP-06, GAP-07, GAP-18)
- Approve a risk methodology and build the first risk register (GAP-02)

**Days 31–60: build what the auditor will ask for first**
- Produce the Statement of Applicability from the risk treatment plan (GAP-04)
- Approve the IR plan and run a tabletop exercise, using the contractor-credential scenario above (GAP-09)
- Apply the security baseline to eu-west-1 (GAP-19); export build logs to long-term storage (GAP-17)
- First quarterly access review (GAP-11), starting with the contractor

**Days 61–90: prove the ISMS operates**
- Supplier tiering and assessments for critical suppliers (GAP-12)
- Complete a full internal audit cycle and management review (GAP-05)
- Re-run every script in this repo. Target: 9 of 9 collector checks passing, 0 orphans, 0 SoD exceptions for the new period, no execution gaps

## Why I built it this way

**The deliverable is a decision, not a list.** Nineteen gaps don't tell leadership what to do on Monday. A "this week" list of three items does. Splitting *security risk* from *certification readiness* points to different owners and deadlines.

**Every finding walks back to evidence.** Risk statement → workpaper → evidence file (hashed) → original system. If a finding is challenged, the answer is "re-run the script", not "trust me".

**Say what passed.** The "reviewed and not flagged" table shows the assessment looked at those controls and judged them fine, rather than missing them.

**Show how findings compound.** Ranked one by one, the contractor's key is a High. Laid out on a timeline, it is the thread that ties six findings together.

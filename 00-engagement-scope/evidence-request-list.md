# Evidence Request List

Tausi Telehealth ISO 27001 readiness · issued 13 Oct 2026 · status as of 23 Oct 2026

**No screenshots.** Every request asks for the system's own artifact: an API export, a log, a file at a commit. A Word document describing a control is not evidence. If a system artifact can't be produced, that becomes a finding about evidence accessibility.

## Requests

| # | Area | Wrong ask (not used) | What was requested | Status | Used in |
|---|---|---|---|---|---|
| R1 | Carve-out | — | AWS SOC 2 Type II report and ISO 27001 certificate from AWS Artifact | ✅ Received | [Scope §5](scope-memo.md#5-shared-responsibility-and-carve-outs) |
| R2 | Carve-out | — | GitHub SOC 2 Type II report | ✅ Received | Scope §5 |
| R3 | AWS config | "Screenshots of IAM settings" | Read-only `SecurityAudit` role for the evidence collector, in both regions | ✅ Received | [02](../02-evidence-collection) |
| R4 | IaC | "25 bucket screenshots" | The bucket module, the root config that calls it, the state files and their S3 object metadata | ✅ Received | [05](../05-iac-audit) |
| R5 | IaC | "Is everything in Terraform?" | Live S3 inventory (`list-buckets` + per-bucket config) and CloudTrail `CreateBucket` events for Q3 | ✅ Received | 05 |
| R6 | Change mgmt | "Give me repo access" | Branch protection settings for `main` + environment rules, the workflow file, CODEOWNERS | ✅ Received | [06](../06-pipeline-audit) |
| R7 | Change mgmt | — | Org audit log filtered to `protected_branch` events, Q3 | ✅ Received | 06 |
| R8 | Change mgmt | "Screenshot of a deploy" | All merged PRs and production deploys for Q3 (API export), the IdP login-to-person mapping, build logs for the period from long-term storage | ⚠️ Partial: 12 of 39 build logs expired, no long-term store | 06, GAP-17 |
| R9 | Continuous | "Dashboard screenshot" | Config rule definitions, recorder status per region, daily evaluation history, all drift events with tickets. **Reason for the 14 Aug recorder stop** | ⚠️ Data received. Reason still open | [07](../07-continuous-monitoring) |
| R10 | Continuous | — | Change record for the 2 Sep security group change (`sg-0a1b2c3d4e5f60002`) | ❌ None exists | 07, GAP-03 |
| R11 | IaC | — | Risk acceptance for ENG-212 (access logging off on uploads bucket) | ❌ None exists | 05, GAP-14 |
| R12 | Change mgmt | — | Engineering assessment of the HIGH Semgrep finding in PR #264 (`app/patients/search.ts:41`) | ⏳ Open (urgent) | 06, GAP-15 |
| R13 | Scope | — | Evidence that account `444455556666` holds no production data (S3 inventory + RDS snapshot list) | ⏳ Open | Scope §2 |
| R14 | Scope | — | Documented legal basis for storing patient data in eu-west-1 | ⏳ Open | Scope §3 |
| R15 | Integrity | — | CloudTrail log file validation for sampled days. Not possible today: validation is off (GAP-06) | ❌ Not available | [04](../04-control-narrative), [08](../08-evidence-evaluation) |
| R16 | ISMS | — | Risk methodology, SoA, internal audit programme, IR plan, supplier register, access reviews | ⚠️ Only IR plan v0.3 draft and a supplier list | [03](../03-gap-assessment) |

## Integrity proofs requested where they exist

- SHA-256 of every collector output (manifest per run, verifiable with `--verify`)
- Git commit SHAs for every code artifact (module, root config, workflow)
- State file S3 `VersionId` and `LastModified`
- CloudTrail digest validation (unavailable, see R15)

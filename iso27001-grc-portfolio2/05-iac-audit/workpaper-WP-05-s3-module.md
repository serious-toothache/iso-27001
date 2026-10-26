# Workpaper WP-05: Patient-data S3 buckets built with Terraform

| | |
|---|---|
| **Client** | Tausi Telehealth Ltd (fictional) |
| **Controls** | ISO/IEC 27001:2022 A.8.9 Configuration management · A.8.24 Use of cryptography · A.8.13 Information backup · A.8.15 Logging · A.5.9 Inventory of assets |
| **SOC 2 crosswalk** | CC6.1 · CC7.2 · CC8.1 · A1.2 · C1.1 |
| **Period** | 1 July – 30 September 2026 (Q3), configuration as of 23 October 2026 |
| **Code reviewed** | `tausi-platform` repo, `terraform/` folder, commit `3f9c2a17e4b8d05c6a91f2e7b3d48c0a5e16f9b2`, module tag `s3-patient-data/v1.4.0` ([excerpt](client-repo)) |
| **State reviewed** | `s3://tausi-terraform-state/prod/s3.tfstate`, serial 57, LastModified `2026-09-18T11:02:44Z`, VersionId `3HL4kqtJlcpXroDTDmJ.rmSpXd3dIbrHY` |
| **Prepared by** | Louisz Rigensky W. · 23 Oct 2026 · AI use logged in [AI-03](../08-evidence-evaluation/ai-use-log.md) |

## 1. Control objective

Every S3 bucket holding patient data is encrypted with a customer-managed key, versioned, access-logged, closed to the public and tagged with its data class. Infrastructure is defined in Terraform, so the objective is met only if (a) the standard module enforces these settings and (b) the module is the only way such buckets get created.

## 2. Test procedure

This is the IaC-aware procedure. It replaces "select 25 buckets and observe their encryption settings".

1. **Inquiry.** Confirm with the Platform Lead that patient-data buckets are deployed only through Terraform via the pipeline. *Confirmed. The README says the same ([README.md](client-repo/modules/s3-patient-data/README.md)).*
2. **Inspection.** Read the module in the standard five-step order: README → `main.tf` → `variables.tf` → validation → `outputs.tf`.
3. **Re-performance.** Diff every Terraform state against the live bucket inventory to find buckets the module never touched (`iac_audit.py orphans`).
4. **Inspection.** Trace each orphan to its `CreateBucket` CloudTrail event.
5. **Inspection.** Check the state backend: remote, encrypted, versioned, access-controlled and logged.
6. **Re-performance.** Reconcile module outputs against the live inventory.

## 3. Population

> All S3 buckets in account `111122223333`, regions af-south-1 and eu-west-1, as enumerated by `aws s3api list-buckets` at `2026-10-23T18:55:10Z` ([`s3-inventory.json`](evidence/s3-inventory.json), SHA-256 `d025663d253195f7bae9aa562454a8bd6e99066ff1343bdcbf0c045cafe1bf27`), **n = 8**.
> Of these, 5 are managed by Terraform state (`prod-s3.tfstate.json` serial 57, `platform.tfstate.json` serial 23), 1 is a documented exception (EXC-01, the state backend) and **2 are in no state at all**.

## 4. Sample and rationale

| What was tested | Size | Why |
|---|---|---|
| The `s3-patient-data` module | **n = 1** | The module is the single source of truth for patient-data buckets. All 3 instances (`patient_records`, `consult_recordings`, `patient_uploads`) are created from it with identical control attributes, so testing the module covers the full population of module-built buckets. **Exception:** one caller input (step 3) varies between instances, so each caller's inputs were also read (3 of 3). |
| Orphan buckets | **All (2 of 2)** | Orphans are the high-risk population. They are outside the pipeline and none of the module's controls apply to them. |
| Changes to the module in the period | Covered in [WP-06](../06-pipeline-audit/workpaper-WP-06-change-management.md) | The module lives in the same repo as the application. Its pull requests were part of the 100% PR population test. |

## 5. Results

### 5.1 Module read

| Step | Claim or attribute | Where | Result |
|---|---|---|---|
| 1 README | Enforces CMK encryption, versioning, **access logging**, Block Public Access, TLS-only, tags | `README.md:6-13` | Claims recorded. The rest of the read tests them |
| 2 main.tf | SSE-KMS with the module's own key | `main.tf:36-37` | ✅ Hard-coded literal + reference |
| 2 main.tf | Key rotation on, 30-day deletion window | `main.tf:3-4` | ✅ Hard-coded |
| 2 main.tf | All four Block Public Access settings; ACLs disabled | `main.tf:17-23`, `main.tf:28` | ✅ Hard-coded |
| 2 main.tf | Versioning `Enabled` | `main.tf:46` | ✅ Hard-coded |
| 2 main.tf | Deny non-TLS requests | `main.tf:57-70` | ✅ Hard-coded |
| 2 main.tf | `DataClass`, `ManagedBy`, `Module` tags | `main.tf:10-14` | ✅ Merged after caller tags, so a caller can't override them |
| 2 main.tf | **Access logging** | `main.tf:51` | ❌ **Conditional:** `count = var.enable_access_logging ? 1 : 0` |
| 3 variables.tf | Control exposed as an input | `variables.tf:26-30` | ❌ `enable_access_logging` (default `true`) lets a caller turn logging off |
| 3 callers | Who turns it off | `live/prod/main.tf:37` | ❌ `module.patient_uploads` sets it to `false` (ticket ENG-212, "too many log objects"). No risk acceptance referenced |
| 4 validation | Naming rule `tausi-(prod\|dr)-*` | `variables.tf:5-8` | ✅ Preventive control, documented |
| 4 validation | Data class must be `confidential` or `restricted` | `variables.tf:15-18` | ✅ Preventive control. Patient data can't be deployed as `internal` |
| 5 outputs | `kms_key_arn`, `versioning_status`, `access_logging_enabled` | `outputs.tf:5-15` | Reconciled in 5.4 |

### 5.2 Orphans (state vs cloud diff)

`python iac_audit.py orphans …` → `Population: 8 buckets | managed by Terraform: 5 | documented exceptions: 1 | orphans: 2`

| Bucket | Region | Created | By / how | CloudTrail event | Module controls missing |
|---|---|---|---|---|---|
| `tausi-tmp-export-carol` | af-south-1 | 2026-08-21 16:03 UTC | `carol.wanjiru`, **console** session, 203.0.113.45 | `9b8e7d6c-…7c6b` | CMK, versioning, access logging, DataClass tag |
| `tausi-dr-restore-test` | eu-west-1 | 2026-09-10 20:41 UTC | `contractor-devops`, **AWS CLI** with long-lived key `AKIAIOSFODNN7EXAMPLE` | `2f3e4d5c-…0718` | CMK, versioning, access logging, DataClass tag |

Both users are the two console users without MFA ([IAM-03](../02-evidence-collection/example-output/run_20261026T151757Z/IAM-03.json)). The CLI key is the 215-day-old key ([IAM-04](../02-evidence-collection/example-output/run_20261026T151757Z/IAM-04.json)). Per the Platform Lead (inquiry), the first bucket holds a patient-list export for an analytics request and the second holds a restored copy of the patient database. **Both contain patient data.** No bucket is in state but missing from the cloud.

`tausi-prod-patient-uploads` was also created in the period (2026-07-15) by the `tausi-ci-deploy` role with the Terraform user agent, which is the expected path.

### 5.3 State backend

| Requirement | Evidence ([`state-backend.json`](evidence/state-backend.json)) | Result |
|---|---|---|
| Remote backend, not a laptop | `backend "s3"` at `live/prod/main.tf:4-11`; state object exists in S3 | ✅ |
| Encrypted at rest | `ServerSideEncryption: aws:kms`; `encrypt = true` at `live/prod/main.tf:8` | ✅ |
| Versioning | `get_bucket_versioning.Status: Enabled` | ✅ |
| Access control | Write limited to `tausi-ci-deploy` and the break-glass role | ✅ |
| Audit logging of reads/writes | `cloudtrail_data_events_on_bucket: false` | ❌ Nobody can show who read the state. It can hold secrets and ARNs. Folded into GAP-06 remediation |

### 5.4 Outputs reconciled to live

| Output | Code says | Live inventory says | Match |
|---|---|---|---|
| `kms_key_arn` | One key per instance | 3 distinct CMKs (`…0001`, `…0002`, `…0003`) | ✅ |
| `versioning_status` | `Enabled` × 3 | `Enabled` × 3 | ✅ |
| `access_logging_enabled` | `true`, `true`, `false` | `true`, `true`, `false` | ✅ Matches code. The code itself is the problem |

## 6. Conclusion

**Exceptions noted.** The module enforces encryption, key rotation, versioning, public-access blocking, TLS-only access and classification tagging as designed, and all three module-built buckets match the code. Two exceptions:

1. **Access logging is not enforced.** The README claims it, but `variables.tf:26` exposes it as an input and `live/prod/main.tf:37` turns it off for `tausi-prod-patient-uploads`. Reads of uploaded patient documents are not logged. → **GAP-14**
2. **The module is not the only path.** 2 of 8 buckets (25%) were created by hand outside Terraform. Both hold patient data and have none of the module's controls. Both were created by users without MFA, one with a stale long-lived key. Nothing (an SCP or AWS Config rule) stopped or flagged them. → **GAP-13**

The test would have surfaced exceptions as: any control attribute that is a variable or a conditional (step 2 and 3), any bucket in the inventory but not in state (orphan diff), or any output that does not reconcile to live configuration.

## 7. Evidence index

| File | SHA-256 |
|---|---|
| [`evidence/s3-inventory.json`](evidence/s3-inventory.json) | `d025663d253195f7bae9aa562454a8bd6e99066ff1343bdcbf0c045cafe1bf27` |
| [`evidence/prod-s3.tfstate.json`](evidence/prod-s3.tfstate.json) | `df1a3aeab37b66a929d9a9fe0a86f8b8b0ac82a7bc01620778684dc6ca491808` |
| [`evidence/platform.tfstate.json`](evidence/platform.tfstate.json) | `9e69cd35dec04c895f2350a38c41eb54aa1e2d68fbc102db6003a0f6a141768b` |
| [`evidence/cloudtrail-createbucket-q3.json`](evidence/cloudtrail-createbucket-q3.json) | `84feb73d7561c8f0c360d2a36240f6cde332be8041632611bab5cbb648dfc4b0` |
| [`evidence/state-backend.json`](evidence/state-backend.json) | `ef5674019ba88853d6ebfc6eb0f84fc37918afa2851b81f554193321e14293d0` |
| [`evidence/known-exceptions.json`](evidence/known-exceptions.json) | `f3d5b447a8193edbe1e0ebcf2d46a292a1188ba2d1c05c3016dbe2afcefca6cc` |
| [`client-repo/modules/s3-patient-data/main.tf`](client-repo/modules/s3-patient-data/main.tf) | `3304678410cf24c449ae3144fdbb29bc28e9ec78eeca0a67a708d3526f2ad6f0` |
| [`client-repo/modules/s3-patient-data/variables.tf`](client-repo/modules/s3-patient-data/variables.tf) | `7849099047cb733c3c3da5c3b4f941a148eac7862e0a1803278bd1136e624330` |
| [`client-repo/live/prod/main.tf`](client-repo/live/prod/main.tf) | `faf74e8ac85c620ae179858fb706f57e68b188fa56563d4818f8855023ddb439` |

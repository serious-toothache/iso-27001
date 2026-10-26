# 05 · IaC Audit: Testing the Module, Not 25 Screenshots

**CGE-AUD Domain 2: Auditing infrastructure as code** · **Files:** [`workpaper-WP-05-s3-module.md`](workpaper-WP-05-s3-module.md) · [`iac_audit.py`](iac_audit.py) · [`client-repo/`](client-repo) · [`evidence/`](evidence) · [`tests/`](tests)

## What I built

Tausi deploys its patient-data buckets with a Terraform compliance module, `s3-patient-data`. This folder audits that setup the way an IaC-literate auditor would:

| Piece | What it is |
|---|---|
| [`client-repo/`](client-repo) | Excerpt of Tausi's `terraform/` folder: the module (README, `main.tf`, `variables.tf`, `outputs.tf`) and the production root config that calls it three times |
| [`evidence/`](evidence) | What the auditor asks for: both state files, the state backend configuration, the live S3 inventory, the CloudTrail `CreateBucket` events for Q3, and the documented-exceptions register |
| [`iac_audit.py`](iac_audit.py) | Two read-only tests: an **orphan finder** (state vs cloud diff, traced to CloudTrail) and a **control-input linter** (finds controls a caller can switch off) |
| [`workpaper-WP-05-s3-module.md`](workpaper-WP-05-s3-module.md) | The signed-off workpaper: 5-step module read, n = 1 rationale, orphan results, state backend checks, conclusion with file:line, commit and hash citations |

## Run it

```bash
cd 05-iac-audit
python iac_audit.py orphans \
  --state evidence/prod-s3.tfstate.json evidence/platform.tfstate.json \
  --inventory evidence/s3-inventory.json \
  --exceptions evidence/known-exceptions.json \
  --cloudtrail evidence/cloudtrail-createbucket-q3.json
```

```
Population: 8 buckets | managed by Terraform: 5 | documented exceptions: 1 | orphans: 2
[ORPHAN] tausi-dr-restore-test (eu-west-1) created 2026-09-10T20:41:55Z by contractor-devops via cli; missing: customer-managed KMS key, versioning, access logging, DataClass tag
[ORPHAN] tausi-tmp-export-carol (af-south-1) created 2026-08-21T16:03:27Z by carol.wanjiru via console; missing: customer-managed KMS key, versioning, access logging, DataClass tag
```

```bash
python iac_audit.py control-inputs client-repo/modules/s3-patient-data --live client-repo/live
```

```
[INPUT ] enable_access_logging (variables.tf:26) lets a caller switch a control off
         disabled by module.patient_uploads at client-repo/live/prod/main.tf:37: enable_access_logging = false # ENG-212: ...
```

Standard library only. Tests: `python -m pytest -q`.

## What it found

| Gap | Finding |
|---|---|
| [GAP-13](../03-gap-assessment/README.md#4-findings) | 2 of 8 buckets were made by hand, outside Terraform. Both hold patient data and have none of the module's controls. Both were made by users without MFA |
| [GAP-14](../03-gap-assessment/README.md#4-findings) | The module README promises access logging, but the code makes it optional and the uploads bucket turns it off |

It also shows what passed: encryption, rotation, versioning, public-access blocking, TLS-only and tagging are hard-coded, and two validation blocks act as preventive controls.

## Why I built it this way

**The module is the population.** Every module-built bucket is a copy of the same code, so testing 25 of them proves nothing more than testing the module once. The real risk is the bucket the module never touched. That's why sampling flips: n = 1 for the module, **all** of the orphans.

**Read the code in the same order every time.** README (the claim) → `main.tf` (is it hard-coded?) → `variables.tf` (can a caller turn it off?) → validation (preventive rules) → outputs (reconcile to live). The README claim is what turned a "looks fine" into a finding. The code doesn't match what the module says it does.

**Orphans need an owner and a how.** "There are 2 unmanaged buckets" starts an argument. "carol.wanjiru created this from the console on 21 August, without MFA" starts a remediation. The CloudTrail join is what makes the finding land.

**Write the rationale down.** "We tested the module once" gets rejected in review. The workpaper uses the n = 1 rationale template and spells out the one place it doesn't hold: the caller input that varies between instances.

## Limitations

- The client repo is an excerpt and the state files are trimmed to the resources under test.
- The orphan diff covers S3 only. The same method applies to any resource type in state: query the provider, cross-reference against state.
- A CSPM tool (Security Hub, Wiz, Prisma, Orca) can run this diff continuously. This script shows the logic an auditor should expect that tool to apply.

# 02 · Evidence Collection Script: Evidence as Code, Not Screenshots

**CGE-AUD Domain 1 (cloud literacy), Domain 6.3 (AWS audit playbook)** · **Files:** [`collect_evidence.py`](collect_evidence.py) · [`sample_data/`](sample_data) · [`tests/`](tests) · [`example-output/`](example-output/run_20261026T151757Z/summary.md)

## What I built

A Python script that pulls security configuration from an AWS account, tests it against 9 checks mapped to ISO/IEC 27001:2022 Annex A **and SOC 2**, and writes each result as a **timestamped, SHA-256-hashed JSON evidence file**. Regional checks run in **every in-scope region**.

| Check | Annex A | SOC 2 | Scope | What it tests |
|---|---|---|---|---|
| IAM-01 | A.5.17 | CC6.1 | global | Password policy meets baseline (14+ chars, complexity, reuse prevention) |
| IAM-02 | A.8.2, A.8.5 | CC6.1 | global | Root user has MFA |
| IAM-03 | A.8.5 | CC6.1 | global | Every console user has MFA (100% population, not a sample) |
| IAM-04 | A.5.17 | CC6.1 | global | Active access keys rotated within 90 days |
| LOG-01 | A.8.15 | CC7.2 | global | A multi-region CloudTrail trail is logging with log file validation |
| S3-01 | A.8.3 | CC6.1, C1.1 | global | S3 Block Public Access on at account level |
| CRY-01 | A.8.24 | CC6.1, C1.1 | **regional** | EBS encryption by default, in every region |
| NET-01 | A.8.20 | CC6.6 | **regional** | No security group exposes SSH/RDP to 0.0.0.0/0 or ::/0, in every region |
| MON-01 | A.8.16 | CC7.2 | **regional** | GuardDuty enabled, in every region |

## What changed in v2

| Change | Why (CGE-AUD) |
|---|---|
| Regional checks loop over every in-scope region (`--regions` live, `regions` in the mock) | 1.2: what you see in one region tells you nothing about another. v1 reported CRY-01 as passing. v2 finds encryption by default **off in the eu-west-1 DR region** |
| `soc2_tsc` in every envelope | 5.4: one collection, two frameworks, zero duplicate testing |
| `scope`, `regions`, `evidence_tier` in every envelope | 6.1: the evidence states where it sits in the hierarchy and what it covers |
| `collector.git_commit` | 2.5: a reviewer can re-run the exact version that produced the evidence |
| `--verify RUN_DIR` | 6.1: authenticity you can verify. Re-hashes every file and its raw data against the manifest |

## Run it (no AWS account needed)

```bash
cd 02-evidence-collection
python collect_evidence.py --mock sample_data/mock_aws_environment.json --as-of 2026-10-23
```

```
[FAIL ] IAM-01  A.5.17         global   3 password policy setting(s) below baseline.
[PASS ] IAM-02  A.8.2, A.8.5   global   Root MFA is enabled.
[FAIL ] IAM-03  A.8.5          global   2 of 5 console user(s) have no MFA.
[FAIL ] IAM-04  A.5.17         global   1 of 3 active access key(s) exceed 90 days.
[FAIL ] LOG-01  A.8.15         global   No trail is multi-region, logging and integrity-validated.
[PASS ] S3-01   A.8.3          global   All four account-level Block Public Access settings are on.
[FAIL ] CRY-01  A.8.24         regional EBS encryption by default is off in 1 of 2 region(s).
[FAIL ] NET-01  A.8.20         regional 1 internet-exposed admin port rule(s) across 2 region(s).
[FAIL ] MON-01  A.8.16         regional GuardDuty is not enabled in 2 of 2 region(s).
```

Prove nothing was edited after collection:

```bash
python collect_evidence.py --verify example-output/run_20261026T151757Z
# example-output/run_20261026T151757Z: intact
```

Against a real account (read-only; attach the AWS managed `SecurityAudit` policy to the role you use):

```bash
pip install -r requirements.txt
python collect_evidence.py --profile audit-readonly --regions af-south-1,eu-west-1
```

Run the tests with `python -m pytest -q`.

## What one piece of evidence looks like

Every file in a run carries the same envelope ([full example](example-output/run_20261026T151757Z/CRY-01.json)):

```json
{
  "evidence_id": "run_20261026T151757Z-CRY-01",
  "check_id": "CRY-01",
  "iso27001_2022_annex_a": ["A.8.24"],
  "soc2_tsc": ["CC6.1", "C1.1"],
  "status": "FAIL",
  "findings": ["New EBS volumes in eu-west-1 are not encrypted by default."],
  "collected_at": "2026-10-26T15:17:57+00:00",
  "as_of": "2026-10-23T00:00:00+00:00",
  "scope": "regional",
  "regions": ["af-south-1", "eu-west-1"],
  "collector": {"name": "collect_evidence.py", "version": "2.0.0", "git_commit": null},
  "evidence_tier": "2 - system output, unsigned (hashed at collection)",
  "api_calls": ["ec2:GetEbsEncryptionByDefault"],
  "raw": {"ebs_encryption_by_default": {"af-south-1": true, "eu-west-1": false}},
  "raw_sha256": "..."
}
```

`manifest.json` stores the SHA-256 of every evidence file. `git_commit` is `null` in the example because it was generated before this version was committed. Runs from a clone record the commit.

## Why I built it this way

**A screenshot proves one moment on one screen.** It can't be re-run, doesn't show the whole population, and nobody can verify it wasn't edited. A JSON file with the API call that produced it, a timestamp and a hash fixes all four problems. An auditor can re-perform the test by running the same script.

**Collection is separated from evaluation.** `collect_live()` only fetches and normalizes data. The checks only evaluate it and never call AWS. That makes the checks unit-testable against a mock environment, and the same logic runs on an auditor's laptop, in a CI pipeline or in a scheduled job.

**Global once, regional everywhere.** IAM and account-level S3 settings are collected once. EC2, security groups and GuardDuty are collected per region. Each envelope says which, so a reviewer can see the coverage.

**`--as-of` makes results reproducible.** Time-based checks like key age change every day. The example run was generated on 26 Oct with `--as-of 2026-10-23` and reproduces the assessment-date result exactly.

**`--fail-on-findings` turns a control into a gate.** In CI, a failing check fails the build, which is how compliance moves from a yearly event to a continuous one.

## Limitations (stated honestly)

- One account per run. A production version would assume a role into each account in the AWS Organization.
- Checks cover configuration, not operation. Operating effectiveness needs period evidence: see [07](../07-continuous-monitoring) and [08](../08-evidence-evaluation/workpaper-WP-08-A.8.5-mfa.md).
- The evidence is tier 2 (hashed but unsigned). Signing the manifest (for example with Sigstore) would move it to tier 1.

## CI

[`.github/workflows/evidence.yml`](../.github/workflows/evidence.yml) runs every test suite and the collector against the mock environment on every push and weekly, verifies the run, and uploads it as a build artifact.

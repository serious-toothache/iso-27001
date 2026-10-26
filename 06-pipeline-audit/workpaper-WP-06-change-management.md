# Workpaper WP-06: Change management and segregation of duties in the pipeline

| | |
|---|---|
| **Client** | Tausi Telehealth Ltd (fictional) |
| **Controls** | ISO/IEC 27001:2022 A.8.32 Change management · A.5.3 Segregation of duties · A.8.25 Secure development life cycle · A.8.29 Security testing in development and acceptance · A.8.4 Access to source code |
| **SOC 2 crosswalk** | CC8.1 · CC6.1 · CC7.1 · CC5.2 |
| **Period** | 1 July – 30 September 2026 (Q3) |
| **System** | GitHub repo `tausi/tausi-platform` (app + Terraform), workflow `.github/workflows/deploy.yml`, environment `production` |
| **Prepared by** | Louisz Rigensky W. · 23 Oct 2026 · AI use logged in [AI-04](../08-evidence-evaluation/ai-use-log.md) |

## 1. Control objective

No single person can get a change into production. Every change to `main` is reviewed and approved by a different human, passes tests and security scanning before deploy, and is approved for production by someone other than its author. The rules can't be bypassed without leaving a record.

## 2. Walkthrough

Scoping question to the Head of Engineering: *"Walk me through what happens when someone pushes a change to production."*

| Expected link | Heard | Note |
|---|---|---|
| Code review | ✅ "Every change is a PR" | |
| Required reviewers | ✅ "One approval" | Not mentioned: admins are exempt |
| Automated tests | ✅ build + unit tests | |
| Security scans | ⚠️ "Semgrep runs on every build" | **Not mentioned:** it no longer blocks anything (since PR #258) |
| Build | ✅ | |
| Manual approval for prod | ✅ `production` environment, Brian or David | Not mentioned: self-approval is allowed |
| Deploy | ✅ OIDC role `tausi-ci-deploy` | |
| Audit log | ✅ GitHub org audit log | Build logs only kept 90 days |

## 3. Evidence requested

Not "give me repo access". The three artifacts that prove the rules, what the checks are, and that the rules held all period:

| Artifact | File |
|---|---|
| Branch protection on `main` + environment rules (GitHub API) | [`branch-protection-main.json`](evidence/branch-protection-main.json) |
| The workflow file | [`deploy.yml`](evidence/deploy.yml) |
| Org audit log, filtered to `protected_branch` events, Q3 | [`org-audit-log-protected-branch.json`](evidence/org-audit-log-protected-branch.json) |
| CODEOWNERS | [`CODEOWNERS`](evidence/CODEOWNERS) |
| Merged PRs, Q3 (GitHub API export) | [`merged-prs-q3.csv`](evidence/merged-prs-q3.csv) |
| Production deployments, Q3 (Deployments API + run metadata) | [`deployments-q3.csv`](evidence/deployments-q3.csv) |
| Org members mapped to people (from the IdP) | [`github-org-members.csv`](evidence/github-org-members.csv) |
| Build log, run 5248 | [`build-log-run-5248.txt`](evidence/build-log-run-5248.txt) |

Full SHA-256 hashes are in [§8](#8-evidence-index).

## 4. Population and sample

> **PRs:** all pull requests merged to `main` of `tausi/tausi-platform` between 2026-07-01 and 2026-09-30, exported from the GitHub API at 2026-10-23T19:18Z, **n = 39**.
> **Deploys:** all runs of the `deploy` workflow that reached the `production` environment in the same period, **n = 39** (one per merge).

**Sample: 100% of both.** The population is already structured data, so testing every item costs no more than testing 25 (event-type strategy, "all if feasible"). Bypass events (admin overrides and protection changes) are anomaly-based and were tested in full from the audit log.

## 5. Test procedure

Re-performed with [`sod_checks.py`](sod_checks.py) (`python sod_checks.py --evidence evidence`) and spot-checked by hand for PRs #241, #255, #258 and #264.

1. **Design.** Inspect branch protection, environment protection, CODEOWNERS and the workflow file (D1–D9).
2. **Population.** For every PR: at least 1 *human* approval, approver ≠ author as **people** (not just logins), approval before merge, no admin override, not merged inside a protection-weakened window, and changes to `.github/workflows/` approved by a pipeline owner (P1–P6).
3. **Bypass events.** Rebuild every period when protection was lowered from `protected_branch.update` events, and list every `policy_override`.
4. **Three-link trace for every deploy.** PR → build log → production approval: same commit SHA, production approver ≠ PR author, no HIGH/CRITICAL scan finding shipped, and the build log is still retrievable (T1–T4).

## 6. Results

### 6.1 Design (9 exceptions)

| # | Exception | Evidence |
|---|---|---|
| D1 | Admins are exempt from branch protection. Admins: `amina-otieno`, `brian-kamau` | `branch-protection-main.json:17-19`, `github-org-members.csv` |
| D2 | No security scan is a required status check (only `build`, `unit-tests`) | `branch-protection-main.json:6-9` |
| D3 | Approvals aren't dismissed when new commits are pushed | `branch-protection-main.json:12` |
| D4 | Last-push approval isn't required | `branch-protection-main.json:14` |
| D5 | Code-owner review isn't required | `branch-protection-main.json:13` |
| D6 | `production` environment allows self-review | `branch-protection-main.json:36` |
| D7 | CODEOWNERS has no owner for `.github/`, so anyone with write access can change the pipeline | `CODEOWNERS:2-3` |
| D8 | `semgrep` job has `continue-on-error: true` | `deploy.yml:28` |
| D9 | `deploy-prod` doesn't depend on `semgrep` | `deploy.yml:35` |

Operating as designed: force pushes and branch deletion are blocked, linear history is required, 1 approval is required, and production needs an environment approval.

### 6.2 Population (6 exceptions in 5 of 39 PRs)

| PR | Test | What happened |
|---|---|---|
| #241 | P1, P5 | `brian-kamau` lowered required approvals to 0 at 09:14 UTC on 12 Aug, merged his own hotfix with no review at 10:02, and restored the rule at 12:47. Window: 3 h 33 min |
| #248 | P1 | The only approval came from `tausi-review-bot[bot]`, an AI reviewer. Treated as a control: it supplements a human review but **can't be the second identity** |
| #255 | P2 | Approved by `joseph-ouma-dev`, the author's second account (same person per the IdP mapping) |
| #258 | P6 | Contractor `kip-devops` made `semgrep` non-blocking and removed it from `deploy-prod.needs`. Approved by a software engineer, not a pipeline owner. **This change caused D8, D9 and T3** |
| #262 | P4 | `amina-otieno` used an admin override to merge with the `unit-tests` check failing |

### 6.3 Trace (14 exceptions in 14 of 39 deploys)

| Run | Test | What happened |
|---|---|---|
| 5133 (PR #241) | T2 | Production approved by `brian-kamau`, the PR author. Combined with #241 above, one person wrote, merged and released the change |
| 5248 (PR #264) | T3 | Semgrep reported a **HIGH SQL injection** at `app/patients/search.ts:41` (patient search by phone). The job exited 1, was marked success, and the change deployed (`build-log-run-5248.txt:9-12, 16`) |
| 5000 – 5079 (12 deploys, 1–24 Jul) | T4 | Build logs past GitHub's 90-day retention and not shipped anywhere else. Tests and scans for these deploys **can no longer be evidenced** |

All 39 deploys trace to the merge commit of their PR (T1: no exceptions).

## 7. Conclusion

**Exceptions noted. The control did not operate effectively for Q3.**

- **Segregation of duties can be bypassed, and was.** 4 of 39 PRs (10%) reached `main` without a review by a second human (#241, #248, #255, #262). One change (#241) was written, merged and released by the same person.
- **The security gate was removed through the pipeline itself.** A contractor's workflow change (#258) went through an approval from someone who doesn't own the pipeline. 16 days later a HIGH SQL injection in patient search reached production (#264). Exploitability is for management to confirm.
- **12 of 39 deploys (31%) can't be evidenced** past the 90-day log retention.

→ **GAP-15** (security gate, #258/#264), **GAP-16** (SoD bypass, D1–D7, #241/#248/#255/#262), **GAP-17** (build log retention).

The test would have surfaced exceptions as: any PR with fewer human approvals than required, any approver who is the same person as the author, any merge inside a weakened-protection window or with an override, any workflow change without an owner's approval, any deploy whose commit, approver, scan result or log doesn't hold up.

## 8. Evidence index

| File | SHA-256 |
|---|---|
| `evidence/branch-protection-main.json` | `3bde0ce58df4264fd4471f9b0b342bd12e51c474adfefd34c0ded821be1d2230` |
| `evidence/deploy.yml` | `21761e34fbede0f1fd683e2a83b8e015d0bff7d6bfe75f72e213777442c98e01` |
| `evidence/org-audit-log-protected-branch.json` | `942c5d042193ffaec39539a198a224601666405d82b667108d4a05ffe85c6d9e` |
| `evidence/CODEOWNERS` | `d49bbb90615d49c154101f0741500dbde99edab8d0d5df94c76380c4dfba007f` |
| `evidence/merged-prs-q3.csv` | `92ab416f7f43cde0ffc54def89e854af2a859aaae8150df77440ce83c909624f` |
| `evidence/deployments-q3.csv` | `9a97bd300d1242dd6ad28ae7b7db153322fe850c7a7d4dbbd87c604cefa01aa4` |
| `evidence/github-org-members.csv` | `b7a7240486d530f098b535c9cfc25410c44e4b6653649029c0316506c83aba3b` |
| `evidence/build-log-run-5248.txt` | `5afa629151747bfca37f07fa3ab905f826051c456b7160a4c8a885cf87c32212` |

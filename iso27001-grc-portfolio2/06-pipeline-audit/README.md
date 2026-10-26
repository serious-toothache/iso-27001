# 06 · Pipeline Audit: Segregation of Duties Moved to the Merge Button

**CGE-AUD Domain 3: Auditing CI/CD pipelines** · **Files:** [`workpaper-WP-06-change-management.md`](workpaper-WP-06-change-management.md) · [`sod_checks.py`](sod_checks.py) · [`evidence/`](evidence) · [`tests/`](tests)

## What I built

Nobody at Tausi deploys by hand. A merge to `main` ships. That makes **who can get code merged** the real segregation-of-duties control. This folder tests it:

| Piece | What it is |
|---|---|
| [`evidence/`](evidence) | The three right asks (branch protection settings, the workflow file, the org audit log filtered to `protected_branch` events) plus CODEOWNERS, every merged PR and production deploy for Q3, an IdP mapping of GitHub logins to people, and one build log |
| [`sod_checks.py`](sod_checks.py) | Tests **design** (can the pipeline enforce SoD?), the **population** (did all 39 PRs follow the rules?) and a **trace** of every deploy (PR → build log → production approval) |
| [`workpaper-WP-06-change-management.md`](workpaper-WP-06-change-management.md) | The workpaper: walkthrough, evidence, 100% population, results and conclusion |

## Run it

```bash
cd 06-pipeline-audit
python sod_checks.py --evidence evidence
```

```
Population: 39 merged PRs, 39 production deploys (100% tested)

== Design: 9 exception(s)
  [D1] branch protection: Admins are exempt (enforce_admins = false).
  [D8] deploy.yml: Job 'semgrep' has continue-on-error: findings never fail the run.
  ...
== Population: 6 exception(s)
  [P1] PR #241: 0 human approval(s), 1 required (no approval).
  [P5] PR #241: Merged while brian-kamau had lowered required approvals (2026-08-12 09:14 to 12:47 UTC).
  [P1] PR #248: 0 human approval(s), 1 required (only a bot approved).
  [P2] PR #255: Approver joseph-ouma-dev is the same person as author joseph-ouma (Joseph Ouma).
  [P6] PR #258: Changed .github/workflows/ without approval from a pipeline owner (...)
  [P4] PR #262: Merged by amina-otieno using an admin override of branch protection.
== Trace: 14 exception(s)
  [T2] run 5133 (PR #241): Production approved by the PR author (brian-kamau).
  [T3] run 5248 (PR #264): Deployed with 1 HIGH/CRITICAL scan finding(s) (semgrep fail).
  [T4] run 5000 (PR #208): Build log no longer retained; the deploy cannot be evidenced.  (x12)
```

Standard library only. Tests: `python -m pytest -q`.

## The story the evidence tells

1. **29 Aug, PR #258.** A contractor makes the Semgrep job `continue-on-error` and removes it from the deploy's `needs`. CODEOWNERS doesn't cover `.github/`, so a software engineer's approval is enough.
2. **14 Sep, PR #264.** Semgrep flags a HIGH SQL injection in patient search. The job exits 1, gets marked as success, and the change deploys.

Neither PR broke a branch-protection rule. **The bypass went through the pipeline itself.** That's why "who can edit the workflow file?" is a test, not an afterthought.

## Why I built it this way

**Test the population, not a sample.** The PR history is already structured data. Checking all 39 costs the same as checking 25, and it found 5 PRs a sample could easily have missed.

**People, not logins.** `joseph-ouma` approving `joseph-ouma-dev` looks fine until you map accounts to humans. The IdP export is evidence, not a convenience.

**Bots are a control, not a reviewer.** An AI reviewer adds value, but it can't be the second identity in "author ≠ approver". PR #248 counts as unreviewed.

**Bypass events live in the audit log, not the settings page.** Today's settings look the same as before 12 August. Only the `protected_branch.update` events show the 3½-hour window when approvals were turned off.

**Three links or it didn't happen.** For each deploy: same commit as the PR, a production approver who isn't the author, scans that passed, and a log that still exists. 12 deploys fail only on the last link. GitHub's 90-day default is shorter than the audit period.

## Limitations

- Data is synthetic but shaped like the GitHub REST API (`/branches/{b}/protection`, `/pulls`, `/deployments`) and the org audit log.
- The approval-before-merge test uses the latest approval timestamp. A production version would also check for commits pushed after approval (which is why D3/D4 matter).

#!/usr/bin/env python3
"""
sod_checks.py - change management and segregation-of-duties tests for a GitHub pipeline.

Runs three layers of tests from the CGE-AUD CI/CD domain against exported evidence:

  Design      Is the pipeline capable of enforcing SoD? (branch protection,
              environment protection, CODEOWNERS, the workflow file itself)
  Population  Did every merged PR follow the rules? Tested on 100% of PRs, because
              the population is already in machine-readable form.
  Trace       For every production deploy: PR -> build log -> approval. Same commit,
              different humans, scans passed, log still retained.

Usage (from 06-pipeline-audit):
    python sod_checks.py --evidence evidence
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

SECURITY_JOBS = ("semgrep", "codeql", "snyk", "trivy", "security-scan")
WORKFLOW_DIR = ".github/workflows/"
WORKFLOW_OWNER_ROLES = {"Platform Lead", "Head of Engineering"}


@dataclass
class Exception_:
    test: str
    ref: str
    detail: str


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _rows(path: Path) -> list[dict]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def load(evidence: Path) -> dict:
    return {
        "prs": _rows(evidence / "merged-prs-q3.csv"),
        "deploys": _rows(evidence / "deployments-q3.csv"),
        "members": {m["login"]: m for m in _rows(evidence / "github-org-members.csv")},
        "protection": json.loads((evidence / "branch-protection-main.json").read_text()),
        "audit": json.loads((evidence / "org-audit-log-protected-branch.json").read_text())["events"],
        "workflow": (evidence / "deploy.yml").read_text(),
        "codeowners": (evidence / "CODEOWNERS").read_text(),
    }


# --- Design --------------------------------------------------------------------------

def check_design(ev: dict) -> list[Exception_]:
    bp, out = ev["protection"], []
    reviews = bp["required_pull_request_reviews"]
    checks = bp["required_status_checks"]["contexts"]
    if not bp["enforce_admins"]["enabled"]:
        out.append(Exception_("D1", "branch protection", "Admins are exempt (enforce_admins = false)."))
    if not any(j in checks for j in SECURITY_JOBS):
        out.append(Exception_("D2", "branch protection",
                              f"No security scan is a required check (required: {', '.join(checks)})."))
    if not reviews["dismiss_stale_reviews"]:
        out.append(Exception_("D3", "branch protection", "Approvals survive new commits (dismiss_stale_reviews = false)."))
    if not reviews["require_last_push_approval"]:
        out.append(Exception_("D4", "branch protection", "The last pusher can merge their own unreviewed push."))
    if not reviews["require_code_owner_reviews"]:
        out.append(Exception_("D5", "branch protection", "CODEOWNERS is advisory (require_code_owner_reviews = false)."))
    for name, env in bp.get("environments", {}).items():
        if not env.get("prevent_self_review"):
            out.append(Exception_("D6", f"environment {name}", "The person who triggers a deploy can approve it."))
    if not re.search(r"^/?\.github/", ev["codeowners"], re.M):
        out.append(Exception_("D7", "CODEOWNERS", "No owner for .github/: anyone with write access can change the pipeline."))
    for job in SECURITY_JOBS:
        block = re.search(rf"^  {job}:\n((?:    .*\n|\n)+)", ev["workflow"], re.M)
        if block and "continue-on-error: true" in block.group(1):
            out.append(Exception_("D8", "deploy.yml", f"Job '{job}' has continue-on-error: findings never fail the run."))
    deploy_needs = re.search(r"^  deploy-prod:\n    needs: \[([^\]]*)\]", ev["workflow"], re.M)
    if deploy_needs and not any(j in deploy_needs.group(1) for j in SECURITY_JOBS):
        out.append(Exception_("D9", "deploy.yml", f"deploy-prod does not wait for a scan (needs: {deploy_needs.group(1)})."))
    return out


# --- Population ------------------------------------------------------------------------

def weakened_windows(audit: list[dict]) -> list[tuple[datetime, datetime, str]]:
    """Periods when required approvals were lowered, from protected_branch.update events."""
    windows, opened = [], None
    for e in sorted(audit, key=lambda e: e["@timestamp"]):
        change = e.get("changes", {}).get("required_approving_review_count")
        if not change:
            continue
        if change["to"] < change["from"] and opened is None:
            opened = (_ts(e["@timestamp"]), e["actor"])
        elif change["to"] > change["from"] and opened:
            windows.append((opened[0], _ts(e["@timestamp"]), opened[1]))
            opened = None
    return windows


def _person(ev: dict, login: str) -> str:
    return ev["members"].get(login, {}).get("person", f"unknown:{login}")


def _is_human(ev: dict, login: str) -> bool:
    return ev["members"].get(login, {}).get("account_type") == "human"


def check_population(ev: dict) -> list[Exception_]:
    required = ev["protection"]["required_pull_request_reviews"]["required_approving_review_count"]
    windows = weakened_windows(ev["audit"])
    overrides = {e.get("pull_request") for e in ev["audit"] if e["action"] == "protected_branch.policy_override"}
    out = []
    for pr in ev["prs"]:
        ref = f"PR #{pr['pr']}"
        approvers = [a for a in pr["approvers"].split(";") if a]
        humans = [a for a in approvers if _is_human(ev, a)]
        author = _person(ev, pr["author"])
        merged = _ts(pr["merged_at"])
        if len(humans) < required:
            what = "only a bot approved" if approvers else "no approval"
            out.append(Exception_("P1", ref, f"{len(humans)} human approval(s), {required} required ({what})."))
        for a in humans:
            if _person(ev, a) == author:
                out.append(Exception_("P2", ref, f"Approver {a} is the same person as author {pr['author']} ({author})."))
        if pr["approved_at"] and _ts(pr["approved_at"]) > merged:
            out.append(Exception_("P3", ref, "Approved after merge."))
        if pr["admin_override"] == "true" or int(pr["pr"]) in overrides:
            out.append(Exception_("P4", ref, f"Merged by {pr['merged_by']} using an admin override of branch protection."))
        for start, end, actor in windows:
            if start <= merged <= end:
                out.append(Exception_("P5", ref, f"Merged while {actor} had lowered required approvals "
                                                 f"({start:%Y-%m-%d %H:%M} to {end:%H:%M} UTC)."))
        if WORKFLOW_DIR in pr["files_changed"] and not any(
                ev["members"].get(a, {}).get("role") in WORKFLOW_OWNER_ROLES for a in humans):
            out.append(Exception_("P6", ref, f"Changed {WORKFLOW_DIR} without approval from a pipeline owner "
                                             f"(author {pr['author']}, approved by {', '.join(approvers) or 'nobody'})."))
    return out


# --- Trace -----------------------------------------------------------------------------

def check_trace(ev: dict) -> list[Exception_]:
    prs = {pr["pr"]: pr for pr in ev["prs"]}
    out = []
    for d in ev["deploys"]:
        ref = f"run {d['run_id']} (PR #{d['pr']})"
        pr = prs.get(d["pr"])
        if not pr:
            out.append(Exception_("T1", ref, "Deploy does not map to a merged PR."))
            continue
        if d["commit_sha"] != pr["merge_commit_sha"]:
            out.append(Exception_("T1", ref, "Deployed commit differs from the PR's merge commit."))
        if _person(ev, d["env_approver"]) == _person(ev, pr["author"]):
            out.append(Exception_("T2", ref, f"Production approved by the PR author ({d['env_approver']})."))
        if int(d["semgrep_high_or_critical"]) > 0:
            out.append(Exception_("T3", ref, f"Deployed with {d['semgrep_high_or_critical']} HIGH/CRITICAL "
                                             f"scan finding(s) (semgrep {d['semgrep_result']})."))
        if d["log_available"] != "true":
            out.append(Exception_("T4", ref, "Build log no longer retained; the deploy cannot be evidenced."))
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Change management and SoD tests for a GitHub pipeline.")
    p.add_argument("--evidence", type=Path, default=Path("evidence"))
    args = p.parse_args(argv)
    ev = load(args.evidence)

    layers = [("Design", check_design(ev)), ("Population", check_population(ev)), ("Trace", check_trace(ev))]
    print(f"Population: {len(ev['prs'])} merged PRs, {len(ev['deploys'])} production deploys (100% tested)\n")
    for name, found in layers:
        print(f"== {name}: {len(found)} exception(s)")
        for e in found:
            print(f"  [{e.test}] {e.ref}: {e.detail}")
        print()
    return 1 if any(found for _, found in layers) else 0


if __name__ == "__main__":
    sys.exit(main())

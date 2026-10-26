#!/usr/bin/env python3
"""
iac_audit.py - auditor checks for an environment built with Terraform.

Two read-only tests from the CGE-AUD IaC domain:

  orphans         State-vs-cloud diff. Every bucket in the cloud that no Terraform
                  state knows about was created outside the pipeline, so the module's
                  controls never applied to it. Each orphan is traced to its
                  CreateBucket event: who made it, when, and with what tool.

  control-inputs  Step 3 of the module read. Flags any variable that lets a caller
                  switch a control off instead of the module hard-coding it.

Usage:
    python iac_audit.py orphans --state evidence/prod-s3.tfstate.json evidence/platform.tfstate.json \
        --inventory evidence/s3-inventory.json --exceptions evidence/known-exceptions.json \
        --cloudtrail evidence/cloudtrail-createbucket-q3.json

    python iac_audit.py control-inputs client-repo/modules/s3-patient-data
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Words in a variable name that suggest it toggles a security control.
CONTROL_WORDS = ("encrypt", "kms", "logging", "log", "versioning", "public", "acl", "tls", "mfa", "lock", "backup")
TOGGLE = re.compile(r"^(enable|disable|allow|skip|use)_|_(enabled|disabled)$")


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


def managed_buckets(state_files: list[Path]) -> dict[str, str]:
    """Bucket name -> state file that manages it."""
    managed = {}
    for path in state_files:
        for res in _load(path).get("resources", []):
            if res.get("mode") == "managed" and res.get("type") == "aws_s3_bucket":
                for inst in res.get("instances", []):
                    managed[inst["attributes"]["bucket"]] = path.name
    return managed


def _how_created(event: dict) -> str:
    agent = event.get("userAgent", "")
    if event.get("sessionCredentialFromConsole") == "true":
        return "console"
    if "Terraform" in agent:
        return "terraform"
    if agent.startswith("aws-cli"):
        return "cli"
    return "other"


def find_orphans(state_files: list[Path], inventory: Path, exceptions: Path | None = None,
                 cloudtrail: Path | None = None) -> dict:
    managed = managed_buckets(state_files)
    buckets = {b["Name"]: b for b in _load(inventory)["buckets"]}
    excepted = {e["resource"]: e for e in (_load(exceptions)["exceptions"] if exceptions else [])}
    created = {}
    if cloudtrail:
        for e in _load(cloudtrail)["Records"]:
            if e["eventName"] == "CreateBucket":
                created[e["requestParameters"]["bucketName"]] = e

    orphans = []
    for name in sorted(set(buckets) - set(managed) - set(excepted)):
        b, e = buckets[name], created.get(name)
        orphans.append({
            "bucket": name, "region": b["Region"], "created": b["CreationDate"],
            "created_by": e["userIdentity"].get("userName") or e["userIdentity"]["arn"] if e else None,
            "created_with": _how_created(e) if e else "unknown (outside the CloudTrail query window)",
            "source_ip": e["sourceIPAddress"] if e else None,
            "missing_module_controls": [label for ok, label in (
                (b["Encryption"]["SSEAlgorithm"] == "aws:kms", "customer-managed KMS key"),
                (b["Versioning"] == "Enabled", "versioning"),
                (b["LoggingEnabled"], "access logging"),
                ("DataClass" in b["Tags"], "DataClass tag")) if not ok],
        })

    return {
        "population": len(buckets),
        "managed": len(set(buckets) & set(managed)),
        "excepted": sorted(set(buckets) & set(excepted)),
        "orphans": orphans,
        "in_state_not_in_cloud": sorted(set(managed) - set(buckets)),
    }


def control_inputs(module_dir: Path) -> list[dict]:
    """Variables in variables.tf that look like an on/off switch for a control."""
    text = (module_dir / "variables.tf").read_text()
    flagged = []
    for match in re.finditer(r'variable\s+"([^"]+)"\s*\{', text):
        name = match.group(1)
        if TOGGLE.search(name) and any(w in name for w in CONTROL_WORDS):
            flagged.append({"variable": name, "file": "variables.tf",
                            "line": text.count("\n", 0, match.start()) + 1})
    return flagged


def callers_disabling(live_dir: Path, variable: str) -> list[dict]:
    """Module calls that set a flagged control variable to false."""
    hits = []
    for tf in sorted(live_dir.rglob("*.tf")):
        lines = tf.read_text().splitlines()
        module = None
        for n, line in enumerate(lines, 1):
            m = re.match(r'\s*module\s+"([^"]+)"', line)
            if m:
                module = m.group(1)
            if re.match(rf"\s*{re.escape(variable)}\s*=\s*false", line):
                hits.append({"module": module, "file": tf.relative_to(live_dir.parent.parent).as_posix(), "line": n,
                             "text": line.strip()})
    return hits


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Auditor checks for Terraform-managed environments.")
    sub = p.add_subparsers(dest="cmd", required=True)
    o = sub.add_parser("orphans", help="Find cloud resources no Terraform state manages.")
    o.add_argument("--state", type=Path, nargs="+", required=True)
    o.add_argument("--inventory", type=Path, required=True)
    o.add_argument("--exceptions", type=Path)
    o.add_argument("--cloudtrail", type=Path)
    c = sub.add_parser("control-inputs", help="Flag controls exposed as module variables.")
    c.add_argument("module_dir", type=Path)
    c.add_argument("--live", type=Path, help="Root config folder to search for callers that switch them off.")
    args = p.parse_args(argv)

    if args.cmd == "orphans":
        r = find_orphans(args.state, args.inventory, args.exceptions, args.cloudtrail)
        print(f"Population: {r['population']} buckets | managed by Terraform: {r['managed']} | "
              f"documented exceptions: {len(r['excepted'])} | orphans: {len(r['orphans'])}")
        for o_ in r["orphans"]:
            print(f"[ORPHAN] {o_['bucket']} ({o_['region']}) created {o_['created']} by {o_['created_by']} "
                  f"via {o_['created_with']}; missing: {', '.join(o_['missing_module_controls']) or 'nothing'}")
        for name in r["in_state_not_in_cloud"]:
            print(f"[DRIFT ] {name} is in state but not in the cloud")
        return 1 if r["orphans"] or r["in_state_not_in_cloud"] else 0

    flagged = control_inputs(args.module_dir)
    for f in flagged:
        print(f"[INPUT ] {f['variable']} ({f['file']}:{f['line']}) lets a caller switch a control off")
        for hit in callers_disabling(args.live, f["variable"]) if args.live else []:
            print(f"         disabled by module.{hit['module']} at {hit['file']}:{hit['line']}: {hit['text']}")
    return 1 if flagged else 0


if __name__ == "__main__":
    sys.exit(main())

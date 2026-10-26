#!/usr/bin/env python3
"""
collect_evidence.py - ISO/IEC 27001:2022 Annex A evidence collector for AWS.

Pulls security configuration from an AWS account (or from a mock snapshot),
evaluates it against baseline checks mapped to Annex A controls (with a SOC 2
crosswalk), and writes timestamped, SHA-256-hashed JSON evidence plus a
Markdown summary. Regional checks run in every in-scope region.

Usage:
    # No AWS account needed - runs against the sample environment
    python collect_evidence.py --mock sample_data/mock_aws_environment.json

    # Live, read-only (needs boto3 and credentials with SecurityAudit)
    python collect_evidence.py --profile audit-readonly --regions af-south-1,eu-west-1

    # Reproducible run for a fixed audit date, failing CI on any finding
    python collect_evidence.py --mock sample_data/mock_aws_environment.json \
        --as-of 2026-10-23 --fail-on-findings

    # Prove a run has not been edited since collection
    python collect_evidence.py --verify example-output/run_20261026T151757Z
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

COLLECTOR_VERSION = "2.0.0"

# --- Baselines (tune these to your own policy) -------------------------------
KEY_MAX_AGE_DAYS = 90
SENSITIVE_PORTS = {22: "SSH", 3389: "RDP"}
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
PASSWORD_BASELINE: dict[str, Any] = {
    "MinimumPasswordLength": 14,
    "RequireSymbols": True,
    "RequireNumbers": True,
    "RequireUppercaseCharacters": True,
    "RequireLowercaseCharacters": True,
    "PasswordReusePrevention": 24,
}

# Where this evidence sits in the CGE-AUD evidence hierarchy (6.1). API output
# is system-generated but unsigned; the SHA-256 manifest makes later edits detectable.
EVIDENCE_TIER = "2 - system output, unsigned (hashed at collection)"


@dataclass
class Result:
    check_id: str
    title: str
    annex_a: list[str]
    soc2_tsc: list[str]
    scope: str                       # global | regional
    status: str                      # PASS | FAIL | ERROR
    summary: str
    findings: list[str] = field(default_factory=list)
    data: Any = None                 # the raw configuration the verdict is based on
    api_calls: list[str] = field(default_factory=list)


# --- Checks -------------------------------------------------------------------
# Each check takes the normalized environment and an "as of" datetime and
# returns a Result. Checks never call AWS directly, so they are fully testable.

def _regions(env: dict) -> list[tuple[str, dict]]:
    """Every in-scope region with its regional settings. Falls back to a single-region snapshot."""
    if "regions" in env:
        return sorted(env["regions"].items())
    return [(env.get("region"), env)]


def check_password_policy(env: dict, as_of: datetime) -> Result:
    meta = dict(check_id="IAM-01", title="IAM password policy meets baseline",
                annex_a=["A.5.17"], soc2_tsc=["CC6.1"], scope="global",
                api_calls=["iam:GetAccountPasswordPolicy"])
    policy = env.get("password_policy")
    if not policy:
        return Result(**meta, status="FAIL", summary="No IAM account password policy is configured.",
                      findings=["No account password policy set (AWS defaults apply)."],
                      data={"password_policy": None})
    findings = []
    for key, required in PASSWORD_BASELINE.items():
        actual = policy.get(key)
        if isinstance(required, bool):
            if actual is not True:
                findings.append(f"{key} is {actual!r}; baseline requires True.")
        elif actual is None or actual < required:
            findings.append(f"{key} is {actual!r}; baseline requires >= {required}.")
    status = "FAIL" if findings else "PASS"
    summary = (f"{len(findings)} password policy setting(s) below baseline."
               if findings else "Password policy meets baseline.")
    return Result(**meta, status=status, summary=summary, findings=findings,
                  data={"password_policy": policy, "baseline": PASSWORD_BASELINE})


def check_root_mfa(env: dict, as_of: datetime) -> Result:
    enabled = bool(env.get("root_mfa_enabled"))
    return Result(check_id="IAM-02", title="Root user has MFA enabled",
                  annex_a=["A.8.2", "A.8.5"], soc2_tsc=["CC6.1"], scope="global",
                  api_calls=["iam:GetAccountSummary"],
                  status="PASS" if enabled else "FAIL",
                  summary="Root MFA is enabled." if enabled else "Root user has no MFA device.",
                  findings=[] if enabled else ["Root user MFA is not enabled."],
                  data={"root_mfa_enabled": enabled})


def check_console_mfa(env: dict, as_of: datetime) -> Result:
    users = [u for u in env.get("credential_report", []) if u["user"] != "<root_account>"]
    console = [u for u in users if u.get("password_enabled")]
    no_mfa = [u["user"] for u in console if not u.get("mfa_active")]
    return Result(check_id="IAM-03", title="All console users have MFA",
                  annex_a=["A.8.5"], soc2_tsc=["CC6.1"], scope="global",
                  api_calls=["iam:GenerateCredentialReport", "iam:GetCredentialReport"],
                  status="FAIL" if no_mfa else "PASS",
                  summary=f"{len(no_mfa)} of {len(console)} console user(s) have no MFA.",
                  findings=[f"User '{u}' can sign in to the console without MFA." for u in no_mfa],
                  data={"console_users": [{"user": u["user"], "mfa_active": u.get("mfa_active")}
                                          for u in console]})


def _parse_date(value: str | None) -> datetime | None:
    if not value or value in ("N/A", "not_supported", "no_information"):
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def check_access_key_age(env: dict, as_of: datetime) -> Result:
    findings, keys = [], []
    for u in env.get("credential_report", []):
        for n in (1, 2):
            if not u.get(f"access_key_{n}_active"):
                continue
            rotated = _parse_date(u.get(f"access_key_{n}_last_rotated"))
            age = (as_of - rotated).days if rotated else None
            keys.append({"user": u["user"], "key": n, "last_rotated": u.get(f"access_key_{n}_last_rotated"),
                         "age_days": age})
            if age is None or age > KEY_MAX_AGE_DAYS:
                findings.append(f"User '{u['user']}' access key {n} is {age} days old "
                                f"(limit {KEY_MAX_AGE_DAYS}).")
    return Result(check_id="IAM-04", title=f"Active access keys rotated within {KEY_MAX_AGE_DAYS} days",
                  annex_a=["A.5.17"], soc2_tsc=["CC6.1"], scope="global",
                  api_calls=["iam:GetCredentialReport"],
                  status="FAIL" if findings else "PASS",
                  summary=f"{len(findings)} of {len(keys)} active access key(s) exceed {KEY_MAX_AGE_DAYS} days.",
                  findings=findings, data={"active_access_keys": keys, "max_age_days": KEY_MAX_AGE_DAYS})


def check_cloudtrail(env: dict, as_of: datetime) -> Result:
    trails = env.get("cloudtrail", {}).get("trails", [])
    compliant = [t for t in trails
                 if t.get("is_multi_region") and t.get("is_logging") and t.get("log_file_validation")]
    findings = []
    if not trails:
        findings.append("No CloudTrail trails exist.")
    for t in trails:
        if t in compliant:
            continue
        issues = [label for key, label in (("is_multi_region", "not multi-region"),
                                           ("is_logging", "not logging"),
                                           ("log_file_validation", "log file validation off"))
                  if not t.get(key)]
        findings.append(f"Trail '{t['name']}': {', '.join(issues)}.")
    ok = bool(compliant)
    return Result(check_id="LOG-01", title="Multi-region CloudTrail with log file validation",
                  annex_a=["A.8.15"], soc2_tsc=["CC7.2"], scope="global",
                  api_calls=["cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus"],
                  status="PASS" if ok else "FAIL",
                  summary=(f"{len(compliant)} compliant trail(s)." if ok
                           else "No trail is multi-region, logging and integrity-validated."),
                  findings=[] if ok else findings, data={"trails": trails})


def check_s3_public_access(env: dict, as_of: datetime) -> Result:
    pab = env.get("s3", {}).get("account_public_access_block")
    settings = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
    missing = list(settings) if not pab else [s for s in settings if not pab.get(s)]
    return Result(check_id="S3-01", title="S3 Block Public Access enabled at account level",
                  annex_a=["A.8.3"], soc2_tsc=["CC6.1", "C1.1"], scope="global",
                  api_calls=["s3control:GetPublicAccessBlock"],
                  status="FAIL" if missing else "PASS",
                  summary=("All four account-level Block Public Access settings are on." if not missing
                           else f"{len(missing)} Block Public Access setting(s) off."),
                  findings=[f"{s} is not enabled at account level." for s in missing],
                  data={"account_public_access_block": pab})


def check_ebs_encryption(env: dict, as_of: datetime) -> Result:
    per_region = {region: bool(r.get("ebs_encryption_by_default")) for region, r in _regions(env)}
    off = [region for region, on in per_region.items() if not on]
    return Result(check_id="CRY-01", title="EBS encryption by default enabled",
                  annex_a=["A.8.24"], soc2_tsc=["CC6.1", "C1.1"], scope="regional",
                  api_calls=["ec2:GetEbsEncryptionByDefault"],
                  status="FAIL" if off else "PASS",
                  summary=(f"EBS encryption by default is off in {len(off)} of {len(per_region)} region(s)."
                           if off else f"New EBS volumes are encrypted by default in all {len(per_region)} region(s)."),
                  findings=[f"New EBS volumes in {region} are not encrypted by default." for region in off],
                  data={"ebs_encryption_by_default": per_region})


def _covers(rule: dict, port: int) -> bool:
    if rule.get("protocol") == "-1":
        return True
    if rule.get("protocol") != "tcp":
        return False
    lo, hi = rule.get("from_port"), rule.get("to_port")
    return lo is not None and hi is not None and lo <= port <= hi


def check_open_admin_ports(env: dict, as_of: datetime) -> Result:
    findings, exposed, evaluated = [], [], {}
    for region, r in _regions(env):
        groups = r.get("security_groups", [])
        evaluated[region] = len(groups)
        for sg in groups:
            for rule in sg.get("ingress", []):
                if rule.get("cidr") not in OPEN_CIDRS:
                    continue
                for port, name in SENSITIVE_PORTS.items():
                    if _covers(rule, port):
                        exposed.append({"region": region, "group_id": sg["group_id"],
                                        "group_name": sg.get("group_name"), "port": port, "cidr": rule["cidr"]})
                        findings.append(f"{region} {sg['group_id']} ({sg.get('group_name')}) allows "
                                        f"{name}/{port} from {rule['cidr']}.")
    return Result(check_id="NET-01", title="No security group exposes SSH/RDP to the internet",
                  annex_a=["A.8.20"], soc2_tsc=["CC6.6"], scope="regional",
                  api_calls=["ec2:DescribeSecurityGroups"],
                  status="FAIL" if findings else "PASS",
                  summary=f"{len(findings)} internet-exposed admin port rule(s) across {len(evaluated)} region(s).",
                  findings=findings,
                  data={"groups_evaluated": evaluated, "exposed_rules": exposed})


def check_guardduty(env: dict, as_of: datetime) -> Result:
    per_region = {region: r.get("guardduty", {}).get("detectors", []) for region, r in _regions(env)}
    off = [region for region, ds in per_region.items() if not any(d.get("status") == "ENABLED" for d in ds)]
    return Result(check_id="MON-01", title="GuardDuty threat detection enabled",
                  annex_a=["A.8.16"], soc2_tsc=["CC7.2"], scope="regional",
                  api_calls=["guardduty:ListDetectors", "guardduty:GetDetector"],
                  status="FAIL" if off else "PASS",
                  summary=(f"GuardDuty is not enabled in {len(off)} of {len(per_region)} region(s)."
                           if off else f"GuardDuty is enabled in all {len(per_region)} region(s)."),
                  findings=[f"No enabled GuardDuty detector in {region}." for region in off],
                  data={"detectors": per_region})


CHECKS: list[Callable[[dict, datetime], Result]] = [
    check_password_policy, check_root_mfa, check_console_mfa, check_access_key_age,
    check_cloudtrail, check_s3_public_access, check_ebs_encryption,
    check_open_admin_ports, check_guardduty,
]


def run_checks(env: dict, as_of: datetime) -> list[Result]:
    results = []
    for check in CHECKS:
        try:
            results.append(check(env, as_of))
        except Exception as exc:  # one broken check must not hide the others
            results.append(Result(check_id=check.__name__, title=check.__name__, annex_a=[], soc2_tsc=[],
                                  scope="unknown", status="ERROR",
                                  summary=f"Check raised {type(exc).__name__}: {exc}"))
    return results


# --- Collection: live AWS -------------------------------------------------------

def _bool(v: str) -> bool:
    return str(v).lower() == "true"


def _collect_region(session, region: str) -> dict:
    ec2 = session.client("ec2", region_name=region)
    groups = []
    for page in ec2.get_paginator("describe_security_groups").paginate():
        for sg in page["SecurityGroups"]:
            ingress = []
            for p in sg.get("IpPermissions", []):
                cidrs = [r["CidrIp"] for r in p.get("IpRanges", [])] + \
                        [r["CidrIpv6"] for r in p.get("Ipv6Ranges", [])]
                for cidr in cidrs:
                    ingress.append({"protocol": p.get("IpProtocol"), "from_port": p.get("FromPort"),
                                    "to_port": p.get("ToPort"), "cidr": cidr})
            groups.append({"group_id": sg["GroupId"], "group_name": sg.get("GroupName"),
                           "vpc_id": sg.get("VpcId"), "ingress": ingress})
    gd = session.client("guardduty", region_name=region)
    return {
        "ebs_encryption_by_default": ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"],
        "security_groups": groups,
        "guardduty": {"detectors": [
            {"id": d, "status": gd.get_detector(DetectorId=d)["Status"]}
            for d in gd.list_detectors()["DetectorIds"]
        ]},
    }


def collect_live(profile: str | None, regions: list[str]) -> dict:
    """Read-only collection. Needs the AWS managed SecurityAudit policy (or equivalent)."""
    try:
        import boto3
        from botocore.exceptions import ClientError
    except ImportError:
        sys.exit("boto3 is required for live mode: pip install -r requirements.txt")

    session = boto3.Session(profile_name=profile, region_name=regions[0] if regions else None)
    regions = regions or [session.region_name]
    account_id = session.client("sts").get_caller_identity()["Account"]
    env: dict[str, Any] = {"source": "live", "account_id": account_id, "home_region": regions[0]}

    # Global services: IAM, account-level S3 settings, trail definitions. Collected once.
    iam = session.client("iam")
    try:
        env["password_policy"] = iam.get_account_password_policy()["PasswordPolicy"]
    except iam.exceptions.NoSuchEntityException:
        env["password_policy"] = None
    env["root_mfa_enabled"] = iam.get_account_summary()["SummaryMap"].get("AccountMFAEnabled", 0) == 1

    for _ in range(15):  # credential report generation is asynchronous
        if iam.generate_credential_report()["State"] == "COMPLETE":
            break
        time.sleep(2)
    content = iam.get_credential_report()["Content"].decode("utf-8")
    env["credential_report"] = [
        {"user": r["user"],
         "password_enabled": _bool(r["password_enabled"]),
         "mfa_active": _bool(r["mfa_active"]),
         "access_key_1_active": _bool(r["access_key_1_active"]),
         "access_key_1_last_rotated": r["access_key_1_last_rotated"],
         "access_key_2_active": _bool(r["access_key_2_active"]),
         "access_key_2_last_rotated": r["access_key_2_last_rotated"]}
        for r in csv.DictReader(io.StringIO(content))
    ]

    ct = session.client("cloudtrail")
    trails = []
    for t in ct.describe_trails(includeShadowTrails=True)["trailList"]:
        status = ct.get_trail_status(Name=t["TrailARN"])
        trails.append({"name": t["Name"], "arn": t["TrailARN"], "home_region": t.get("HomeRegion"),
                       "is_multi_region": t.get("IsMultiRegionTrail", False),
                       "log_file_validation": t.get("LogFileValidationEnabled", False),
                       "is_logging": status.get("IsLogging", False),
                       "s3_bucket": t.get("S3BucketName"), "kms_key_id": t.get("KmsKeyId")})
    env["cloudtrail"] = {"trails": trails}

    try:
        pab = session.client("s3control").get_public_access_block(AccountId=account_id)
        env["s3"] = {"account_public_access_block": pab["PublicAccessBlockConfiguration"]}
    except ClientError:
        env["s3"] = {"account_public_access_block": None}

    # Regional services: what you see in one region tells you nothing about another.
    env["regions"] = {region: _collect_region(session, region) for region in regions}
    return env


# --- Evidence output ----------------------------------------------------------------

def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _collector_commit() -> str | None:
    """Git commit of the collector itself, so a reviewer can re-run the exact version (2.5)."""
    root = Path(__file__).resolve().parent.parent
    try:
        top = subprocess.run(["git", "-C", str(root), "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True, check=True).stdout.strip()
        if Path(top).resolve() != root:   # inside some other repository, not this one
            return None
        return subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def write_evidence(env: dict, results: list[Result], out_root: Path,
                   collected_at: datetime, as_of: datetime) -> Path:
    run_id = collected_at.strftime("run_%Y%m%dT%H%M%SZ")
    run_dir = out_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    regions = [region for region, _ in _regions(env)]
    collector = {"name": "collect_evidence.py", "version": COLLECTOR_VERSION, "git_commit": _collector_commit()}

    files = []
    for r in results:
        envelope = {
            "evidence_id": f"{run_id}-{r.check_id}",
            "check_id": r.check_id,
            "title": r.title,
            "iso27001_2022_annex_a": r.annex_a,
            "soc2_tsc": r.soc2_tsc,
            "status": r.status,
            "summary": r.summary,
            "findings": r.findings,
            "collected_at": collected_at.isoformat(),
            "as_of": as_of.isoformat(),
            "account_id": env.get("account_id"),
            "scope": r.scope,
            "regions": regions if r.scope == "regional" else ["global"],
            "environment_source": env.get("source", "unknown"),
            "collector": collector,
            "evidence_tier": EVIDENCE_TIER,
            "api_calls": r.api_calls,
            "raw": r.data,
            "raw_sha256": _sha256(_canonical(r.data)),
        }
        body = json.dumps(envelope, indent=2, default=str).encode("utf-8")
        path = run_dir / f"{r.check_id}.json"
        path.write_bytes(body)
        files.append({"file": path.name, "check_id": r.check_id, "status": r.status,
                      "sha256": _sha256(body)})

    counts = {s: sum(1 for r in results if r.status == s) for s in ("PASS", "FAIL", "ERROR")}
    manifest = {"run_id": run_id, "collected_at": collected_at.isoformat(), "as_of": as_of.isoformat(),
                "account_id": env.get("account_id"), "regions": regions,
                "environment_source": env.get("source", "unknown"),
                "collector": collector, "counts": counts, "evidence": files}
    # Explicit "\n" so files hash the same on every OS.
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), newline="\n")

    icon = {"PASS": "✅ PASS", "FAIL": "❌ FAIL", "ERROR": "⚠️ ERROR"}
    lines = [f"# Evidence summary: {run_id}", "",
             f"- **Account:** {env.get('account_id')} · **Regions:** {', '.join(regions)} "
             f"· **Source:** {env.get('source', 'unknown')}",
             f"- **Collected:** {collected_at.isoformat()} · **As of:** {as_of.date().isoformat()}",
             f"- **Collector:** v{COLLECTOR_VERSION} · commit `{collector['git_commit'] or 'not committed'}`",
             f"- **Result:** {counts['PASS']} pass · {counts['FAIL']} fail · {counts['ERROR']} error", "",
             "| Check | Annex A | SOC 2 | Scope | Status | Summary | Evidence |", "|---|---|---|---|---|---|---|"]
    for r in results:
        lines.append(f"| {r.check_id}: {r.title} | {', '.join(r.annex_a)} | {', '.join(r.soc2_tsc)} "
                     f"| {r.scope} | {icon[r.status]} | {r.summary} | [`{r.check_id}.json`]({r.check_id}.json) |")
    lines += ["", "Integrity: each file's SHA-256 is recorded in [`manifest.json`](manifest.json). "
              "Run `python collect_evidence.py --verify <run folder>` to detect tampering.", ""]
    (run_dir / "summary.md").write_text("\n".join(lines), encoding="utf-8", newline="\n")
    return run_dir


def verify_run(run_dir: Path) -> list[str]:
    """Re-hash every file in a run against its manifest. Returns a list of problems (empty = intact)."""
    manifest = json.loads((run_dir / "manifest.json").read_text())
    problems = []
    for entry in manifest["evidence"]:
        path = run_dir / entry["file"]
        if not path.exists():
            problems.append(f"{entry['file']}: missing")
            continue
        body = path.read_bytes()
        if _sha256(body) != entry["sha256"]:
            problems.append(f"{entry['file']}: file hash does not match manifest")
            continue
        envelope = json.loads(body)
        if _sha256(_canonical(envelope["raw"])) != envelope["raw_sha256"]:
            problems.append(f"{entry['file']}: raw data hash does not match raw_sha256")
    return problems


# --- CLI -----------------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Collect ISO 27001 Annex A evidence from AWS.")
    src = p.add_mutually_exclusive_group()
    src.add_argument("--mock", type=Path, help="Path to a mock environment JSON (no AWS needed).")
    src.add_argument("--profile", help="AWS CLI profile for live, read-only collection.")
    src.add_argument("--verify", type=Path, metavar="RUN_DIR", help="Verify a run folder against its manifest.")
    p.add_argument("--regions", help="Comma-separated in-scope regions (live mode). The first is the home region.")
    p.add_argument("--as-of", help="Evaluate time-based checks as of this date (YYYY-MM-DD).")
    p.add_argument("--output", type=Path, default=Path("evidence"), help="Output folder (default: evidence).")
    p.add_argument("--fail-on-findings", action="store_true", help="Exit 1 if any check fails (for CI).")
    args = p.parse_args(argv)

    if args.verify:
        problems = verify_run(args.verify)
        for problem in problems:
            print(f"[TAMPERED] {problem}")
        print(f"{args.verify}: {'intact' if not problems else f'{len(problems)} problem(s)'}")
        return 1 if problems else 0

    collected_at = datetime.now(timezone.utc).replace(microsecond=0)
    as_of = (datetime.fromisoformat(args.as_of).replace(tzinfo=timezone.utc)
             if args.as_of else collected_at)

    if args.mock:
        env = json.loads(args.mock.read_text())
        env.setdefault("source", f"mock:{args.mock.name}")
    else:
        regions = [r.strip() for r in args.regions.split(",")] if args.regions else []
        env = collect_live(args.profile, regions)

    results = run_checks(env, as_of)
    run_dir = write_evidence(env, results, args.output, collected_at, as_of)

    for r in results:
        print(f"[{r.status:5}] {r.check_id:7} {', '.join(r.annex_a):14} {r.scope:8} {r.summary}")
    print(f"\nEvidence written to {run_dir}")

    failed = any(r.status != "PASS" for r in results)
    return 1 if (args.fail_on_findings and failed) else 0


if __name__ == "__main__":
    sys.exit(main())

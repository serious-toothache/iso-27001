#!/usr/bin/env python3
"""
analyze_continuous.py - operating-effectiveness tests for continuous controls.

Three tests from the CGE-AUD continuous-controls domain:

  executions  Did the control run every day of the period? Gaps in the execution
              log mean the control was off, whatever the dashboard shows today.
  drift       Detect -> Alert -> Ticket -> Remediate -> Validate. Finds where the
              chain broke for every drift event, and measures MTTR against SLA.
  events      Filter CloudTrail by eventName / user / time and answer the 5 Ws
              (who, what, when, where, which) for each event.

Usage (from 07-continuous-monitoring):
    python analyze_continuous.py executions evidence/config-rule-evaluations-q3.csv --start 2026-07-01 --end 2026-09-30
    python analyze_continuous.py drift evidence/drift-events-q3.csv --status evidence/config-recorder-status.json --as-of 2026-10-23
    python analyze_continuous.py events evidence/cloudtrail-sample-q3.json --event-name StopConfigurationRecorder
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path


def _rows(path: Path) -> list[dict]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def _ts(value: str) -> datetime | None:
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


# --- Executions ----------------------------------------------------------------------

def execution_gaps(rows: list[dict], start: date, end: date) -> dict[str, list[tuple[date, date]]]:
    """Per rule, the runs of consecutive days with no evaluation."""
    ran: dict[str, set[date]] = {}
    for r in rows:
        ran.setdefault(r["rule"], set()).add(date.fromisoformat(r["date"]))
    gaps: dict[str, list[tuple[date, date]]] = {}
    for rule, days in ran.items():
        gaps[rule], d, opened = [], start, None
        while d <= end:
            if d not in days and opened is None:
                opened = d
            elif d in days and opened is not None:
                gaps[rule].append((opened, d - timedelta(days=1)))
                opened = None
            d += timedelta(days=1)
        if opened is not None:
            gaps[rule].append((opened, end))
    return gaps


# --- Drift workflow --------------------------------------------------------------------

def drift_breakpoints(rows: list[dict], sla_days: dict[str, int], as_of: datetime) -> list[dict]:
    """Where each drift event's Detect -> Alert -> Ticket -> Remediate -> Validate chain broke."""
    results = []
    for r in rows:
        detected = _ts(r["detected_at"])
        remediated = _ts(r["remediated_at"])
        sla = timedelta(days=sla_days[r["severity"]])
        if not r["alerted_at"]:
            status = "broken alert"
        elif not r["ticket"]:
            status = "broken response"
        elif not remediated:
            status = "broken remediation" if as_of - detected > sla else "open within SLA"
        elif remediated - detected > sla:
            status = "remediated late"
        elif not r["validated_at"]:
            status = "not validated"
        else:
            status = "ok"
        age = (remediated or as_of) - detected
        results.append({"drift_id": r["drift_id"], "rule": r["rule"], "resource": r["resource"],
                        "severity": r["severity"], "status": status,
                        "hours_to_remediate": round((remediated - detected).total_seconds() / 3600, 1) if remediated else None,
                        "open_days": None if remediated else age.days, "sla_days": sla.days, "ticket": r["ticket"] or None})
    return results


def mttr_hours(results: list[dict]) -> float | None:
    done = [r["hours_to_remediate"] for r in results if r["hours_to_remediate"] is not None]
    return round(sum(done) / len(done), 1) if done else None


def unalerted_rules(status: dict, rules: set[str]) -> list[str]:
    """Rules whose NON_COMPLIANT results the alert routing never sends anywhere."""
    routed = set(status["alerting"]["event_pattern"]["detail"].get("configRuleName", rules))
    return sorted(rules - routed)


def unrecorded_regions(status: dict) -> list[str]:
    return sorted(region for region, s in status["regions"].items() if not s.get("recording"))


# --- CloudTrail 5 Ws -------------------------------------------------------------------

def five_ws(path: Path, event_name: str | None = None, user: str | None = None,
            start: datetime | None = None, end: datetime | None = None) -> list[dict]:
    out = []
    for e in json.loads(path.read_text())["Records"]:
        who = e["userIdentity"].get("userName") or e["userIdentity"].get("arn")
        when = _ts(e["eventTime"])
        if event_name and e["eventName"] != event_name:
            continue
        if user and who != user:
            continue
        if (start and when < start) or (end and when > end):
            continue
        how = "console" if e.get("sessionCredentialFromConsole") == "true" or e["eventName"] == "ConsoleLogin" \
            else "cli" if e.get("userAgent", "").startswith("aws-cli") else "other"
        out.append({"who": who, "what": e["eventName"], "when": e["eventTime"],
                    "where": f"{e['sourceIPAddress']} / {e['awsRegion']}",
                    "which": e.get("requestParameters") or e.get("additionalEventData"),
                    "how": how, "key": e["userIdentity"].get("accessKeyId"), "event_id": e["eventID"]})
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Operating-effectiveness tests for continuous controls.")
    sub = p.add_subparsers(dest="cmd", required=True)
    x = sub.add_parser("executions")
    x.add_argument("csv", type=Path)
    x.add_argument("--start", required=True)
    x.add_argument("--end", required=True)
    d = sub.add_parser("drift")
    d.add_argument("csv", type=Path)
    d.add_argument("--status", type=Path, required=True)
    d.add_argument("--as-of", required=True)
    e = sub.add_parser("events")
    e.add_argument("json", type=Path)
    e.add_argument("--event-name")
    e.add_argument("--user")
    args = p.parse_args(argv)

    if args.cmd == "executions":
        start, end = date.fromisoformat(args.start), date.fromisoformat(args.end)
        days = (end - start).days + 1
        problems = 0
        for rule, gaps in sorted(execution_gaps(_rows(args.csv), start, end).items()):
            missing = sum((b - a).days + 1 for a, b in gaps)
            print(f"{rule:38} ran {days - missing}/{days} days"
                  + "".join(f"  GAP {a} to {b} ({(b - a).days + 1} days)" for a, b in gaps))
            problems += bool(gaps)
        return 1 if problems else 0

    if args.cmd == "drift":
        status = json.loads(args.status.read_text())
        as_of = datetime.fromisoformat(args.as_of).replace(tzinfo=timezone.utc)
        rows = _rows(args.csv)
        results = drift_breakpoints(rows, status["remediation_sla_days"], as_of)
        for r in results:
            extra = (f"{r['hours_to_remediate']} h to remediate" if r["hours_to_remediate"] is not None
                     else f"open {r['open_days']} days (SLA {r['sla_days']})")
            print(f"[{r['status']:18}] {r['drift_id']} {r['rule']} {r['resource']} | ticket {r['ticket'] or '-'} | {extra}")
        print(f"\nMTTR (remediated events): {mttr_hours(results)} h")
        for rule in unalerted_rules(status, {r["rule"] for r in rows}):
            print(f"Alert routing ignores rule: {rule}")
        for region in unrecorded_regions(status):
            print(f"No Config recorder in region: {region}")
        return 1 if any(r["status"] != "ok" for r in results) else 0

    for ev in five_ws(args.json, args.event_name, args.user):
        print(f"WHO {ev['who']} ({ev['how']}{', key ' + ev['key'] if ev['key'] else ''}) | WHAT {ev['what']} | "
              f"WHEN {ev['when']} | WHERE {ev['where']} | WHICH {json.dumps(ev['which'])[:120]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

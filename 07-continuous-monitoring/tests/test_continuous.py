"""Tests for analyze_continuous.py. Run from 07-continuous-monitoring: python -m pytest -q"""
import json
import sys
from datetime import date, datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import analyze_continuous as ac  # noqa: E402

EV = ROOT / "evidence"
AS_OF = datetime(2026, 10, 23, tzinfo=timezone.utc)
STATUS = json.loads((EV / "config-recorder-status.json").read_text())


def drift():
    rows = ac._rows(EV / "drift-events-q3.csv")
    return {r["drift_id"]: r for r in ac.drift_breakpoints(rows, STATUS["remediation_sla_days"], AS_OF)}


def test_recorder_outage_shows_as_the_same_gap_for_every_rule():
    gaps = ac.execution_gaps(ac._rows(EV / "config-rule-evaluations-q3.csv"), date(2026, 7, 1), date(2026, 9, 30))
    assert set(gaps) == {"restricted-ssh", "s3-bucket-versioning-enabled", "mfa-enabled-for-iam-console-access"}
    assert all(g == [(date(2026, 8, 14), date(2026, 8, 19))] for g in gaps.values())


def test_gap_at_end_of_period_is_reported():
    rows = [{"date": "2026-09-28", "rule": "r"}]
    assert ac.execution_gaps(rows, date(2026, 9, 28), date(2026, 9, 30)) == {"r": [(date(2026, 9, 29), date(2026, 9, 30))]}


def test_each_breakpoint_type_is_found():
    status = {k: v["status"] for k, v in drift().items()}
    assert status == {"DRF-01": "ok", "DRF-02": "broken response", "DRF-03": "broken response",
                      "DRF-04": "broken alert", "DRF-05": "broken remediation", "DRF-06": "ok"}


def test_mttr_uses_only_remediated_events():
    assert ac.mttr_hours(list(drift().values())) == 21.4


def test_open_ticket_inside_sla_is_not_a_failure():
    rows = [{"drift_id": "X", "rule": "r", "resource": "x", "severity": "high", "detected_at": "2026-10-20T00:00:00Z",
             "alerted_at": "2026-10-20T00:01:00Z", "ticket": "TT-1", "ticket_opened_at": "2026-10-20T01:00:00Z",
             "remediated_at": "", "validated_at": ""}]
    assert ac.drift_breakpoints(rows, {"high": 7}, AS_OF)[0]["status"] == "open within SLA"


def test_alert_routing_and_region_coverage_gaps():
    rules = {"restricted-ssh", "s3-bucket-versioning-enabled", "mfa-enabled-for-iam-console-access"}
    assert ac.unalerted_rules(STATUS, rules) == ["s3-bucket-versioning-enabled"]
    assert ac.unrecorded_regions(STATUS) == ["eu-west-1"]


def test_five_ws_filter_by_event_and_user():
    [stop] = ac.five_ws(EV / "cloudtrail-sample-q3.json", event_name="StopConfigurationRecorder")
    assert (stop["who"], stop["how"], stop["key"]) == ("contractor-devops", "cli", "AKIAIOSFODNN7EXAMPLE")
    assert len(ac.five_ws(EV / "cloudtrail-sample-q3.json", user="contractor-devops")) == 3

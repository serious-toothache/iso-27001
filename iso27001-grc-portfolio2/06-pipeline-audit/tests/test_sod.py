"""Tests for sod_checks.py. Run from 06-pipeline-audit: python -m pytest -q"""
import copy
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import sod_checks as st  # noqa: E402

EV = st.load(ROOT / "evidence")


def ids(found):
    return sorted((e.test, e.ref) for e in found)


def test_design_flags_every_weak_setting_but_not_the_good_ones():
    tests = {e.test for e in st.check_design(EV)}
    assert tests == {"D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9"}
    # force pushes and deletions are blocked, so nothing about them is reported
    assert not any("force push" in e.detail.lower() or "deletion" in e.detail.lower() for e in st.check_design(EV))


def test_population_exceptions_are_exactly_the_planted_ones():
    assert ids(st.check_population(EV)) == [
        ("P1", "PR #241"), ("P1", "PR #248"), ("P2", "PR #255"),
        ("P4", "PR #262"), ("P5", "PR #241"), ("P6", "PR #258")]


def test_bot_approval_does_not_count_as_a_human_review():
    e = next(e for e in st.check_population(EV) if e.ref == "PR #248")
    assert "only a bot approved" in e.detail


def test_second_account_is_matched_to_the_same_person():
    e = next(e for e in st.check_population(EV) if e.test == "P2")
    assert "joseph-ouma-dev" in e.detail and "Joseph Ouma" in e.detail


def test_weakened_window_is_rebuilt_from_the_audit_log():
    [(start, end, actor)] = st.weakened_windows(EV["audit"])
    assert (actor, start.isoformat(), end.isoformat()) == (
        "brian-kamau", "2026-08-12T09:14:02+00:00", "2026-08-12T12:47:30+00:00")


def test_trace_catches_self_approved_deploy_and_unblocked_finding():
    found = {(e.test, e.ref) for e in st.check_trace(EV) if e.test != "T4"}
    assert found == {("T2", "run 5133 (PR #241)"), ("T3", "run 5248 (PR #264)")}


def test_retention_gap_covers_only_deploys_older_than_90_days():
    expired = [e for e in st.check_trace(EV) if e.test == "T4"]
    assert len(expired) == 12


def test_mismatched_commit_breaks_the_trace():
    ev = copy.deepcopy(EV)
    ev["deploys"][5]["commit_sha"] = "0" * 40
    assert "T1" in {e.test for e in st.check_trace(ev)}


def test_hardened_settings_clear_the_design_layer():
    ev = copy.deepcopy(EV)
    bp = ev["protection"]
    bp["enforce_admins"]["enabled"] = True
    bp["required_status_checks"]["contexts"].append("semgrep")
    bp["required_pull_request_reviews"].update(dismiss_stale_reviews=True, require_last_push_approval=True,
                                               require_code_owner_reviews=True)
    bp["environments"]["production"]["prevent_self_review"] = True
    ev["codeowners"] += "/.github/     @tausi/platform\n"
    ev["workflow"] = ev["workflow"].replace("    continue-on-error: true # PR #258: semgrep flaky, unblock deploys\n", "")
    ev["workflow"] = ev["workflow"].replace("needs: [build, unit-tests]", "needs: [build, unit-tests, semgrep]")
    assert st.check_design(ev) == []

"""Tests for iac_audit.py. Run from 05-iac-audit: python -m pytest -q"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import iac_audit as ia  # noqa: E402

EV = ROOT / "evidence"
STATES = [EV / "prod-s3.tfstate.json", EV / "platform.tfstate.json"]


def run():
    return ia.find_orphans(STATES, EV / "s3-inventory.json", EV / "known-exceptions.json",
                           EV / "cloudtrail-createbucket-q3.json")


def test_finds_exactly_the_two_hand_made_buckets():
    assert [o["bucket"] for o in run()["orphans"]] == ["tausi-dr-restore-test", "tausi-tmp-export-carol"]


def test_documented_exception_is_not_an_orphan():
    r = run()
    assert r["excepted"] == ["tausi-terraform-state"]
    assert r["population"] == r["managed"] + len(r["excepted"]) + len(r["orphans"])


def test_orphans_are_traced_to_who_made_them_and_how():
    by_name = {o["bucket"]: o for o in run()["orphans"]}
    assert (by_name["tausi-tmp-export-carol"]["created_by"], by_name["tausi-tmp-export-carol"]["created_with"]) \
        == ("carol.wanjiru", "console")
    assert (by_name["tausi-dr-restore-test"]["created_by"], by_name["tausi-dr-restore-test"]["created_with"]) \
        == ("contractor-devops", "cli")


def test_orphans_lack_the_module_controls():
    for o in run()["orphans"]:
        assert set(o["missing_module_controls"]) == {
            "customer-managed KMS key", "versioning", "access logging", "DataClass tag"}


def test_without_exceptions_file_the_backend_bucket_shows_up(tmp_path):
    r = ia.find_orphans(STATES, EV / "s3-inventory.json")
    assert "tausi-terraform-state" in [o["bucket"] for o in r["orphans"]]


def test_bucket_deleted_outside_terraform_is_reported(tmp_path):
    inv = json.loads((EV / "s3-inventory.json").read_text())
    inv["buckets"] = [b for b in inv["buckets"] if b["Name"] != "tausi-prod-consult-recordings"]
    path = tmp_path / "inv.json"
    path.write_text(json.dumps(inv))
    assert ia.find_orphans(STATES, path)["in_state_not_in_cloud"] == ["tausi-prod-consult-recordings"]


def test_logging_switch_is_flagged_and_traced_to_the_caller():
    module = ROOT / "client-repo" / "modules" / "s3-patient-data"
    flagged = ia.control_inputs(module)
    assert [f["variable"] for f in flagged] == ["enable_access_logging"]
    hits = ia.callers_disabling(ROOT / "client-repo" / "live", "enable_access_logging")
    assert [h["module"] for h in hits] == ["patient_uploads"]

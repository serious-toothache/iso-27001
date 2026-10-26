"""Unit tests for the evidence checks. Run from 02-evidence-collection: python -m pytest -q"""
import copy
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import collect_evidence as ce  # noqa: E402

AS_OF = datetime(2026, 10, 23, tzinfo=timezone.utc)
MOCK = json.loads((HERE.parent / "sample_data" / "mock_aws_environment.json").read_text())


def statuses(env):
    return {r.check_id: r.status for r in ce.run_checks(env, AS_OF)}


def test_mock_environment_produces_expected_results():
    assert statuses(MOCK) == {
        "IAM-01": "FAIL", "IAM-02": "PASS", "IAM-03": "FAIL", "IAM-04": "FAIL",
        "LOG-01": "FAIL", "S3-01": "PASS", "CRY-01": "FAIL", "NET-01": "FAIL", "MON-01": "FAIL",
    }


def test_console_mfa_names_the_right_users():
    result = ce.check_console_mfa(MOCK, AS_OF)
    assert sorted(f.split("'")[1] for f in result.findings) == ["carol.wanjiru", "contractor-devops"]


def test_key_age_flags_only_stale_key():
    result = ce.check_access_key_age(MOCK, AS_OF)
    assert len(result.findings) == 1 and "contractor-devops" in result.findings[0]


def test_ssh_open_to_world_is_caught_but_https_is_not():
    result = ce.check_open_admin_ports(MOCK, AS_OF)
    assert [e["group_id"] for e in result.data["exposed_rules"]] == ["sg-0a1b2c3d4e5f60002"]


def test_all_traffic_rule_counts_as_exposed():
    env = {"security_groups": [{"group_id": "sg-x", "ingress": [
        {"protocol": "-1", "from_port": None, "to_port": None, "cidr": "0.0.0.0/0"}]}]}
    assert len(ce.check_open_admin_ports(env, AS_OF).findings) == 2  # SSH and RDP


def test_regional_check_fails_on_the_one_region_that_is_off():
    # af-south-1 encrypts by default; the eu-west-1 DR region does not. Testing one region would miss it.
    result = ce.check_ebs_encryption(MOCK, AS_OF)
    assert result.status == "FAIL" and result.findings == [
        "New EBS volumes in eu-west-1 are not encrypted by default."]
    only_home = copy.deepcopy(MOCK)
    del only_home["regions"]["eu-west-1"]
    assert ce.check_ebs_encryption(only_home, AS_OF).status == "PASS"


def test_global_and_regional_scope_is_declared():
    scopes = {r.check_id: r.scope for r in ce.run_checks(MOCK, AS_OF)}
    assert {c for c, s in scopes.items() if s == "regional"} == {"CRY-01", "NET-01", "MON-01"}


def test_every_check_has_iso_and_soc2_mapping():
    for r in ce.run_checks(MOCK, AS_OF):
        assert r.annex_a and r.soc2_tsc, r.check_id


def test_remediated_environment_passes_everything():
    env = copy.deepcopy(MOCK)
    env["password_policy"].update(MinimumPasswordLength=14, RequireSymbols=True, PasswordReusePrevention=24)
    for u in env["credential_report"]:
        if u["password_enabled"]:
            u["mfa_active"] = True
        if u["access_key_1_active"]:
            u["access_key_1_last_rotated"] = "2026-10-01T00:00:00+00:00"
    env["cloudtrail"]["trails"][0].update(is_multi_region=True, log_file_validation=True)
    env["regions"]["af-south-1"]["security_groups"][1]["ingress"].pop()  # drop the SSH rule
    for region in env["regions"].values():
        region["ebs_encryption_by_default"] = True
        region["guardduty"]["detectors"] = [{"id": "abc", "status": "ENABLED"}]
    assert set(statuses(env).values()) == {"PASS"}


def test_evidence_files_are_hashed(tmp_path):
    results = ce.run_checks(MOCK, AS_OF)
    run_dir = ce.write_evidence(MOCK, results, tmp_path, AS_OF, AS_OF)
    manifest = json.loads((run_dir / "manifest.json").read_text())
    for entry in manifest["evidence"]:
        assert ce._sha256((run_dir / entry["file"]).read_bytes()) == entry["sha256"]
    assert ce.verify_run(run_dir) == []


def test_verify_detects_an_edited_evidence_file(tmp_path):
    run_dir = ce.write_evidence(MOCK, ce.run_checks(MOCK, AS_OF), tmp_path, AS_OF, AS_OF)
    path = run_dir / "IAM-03.json"
    path.write_text(path.read_text().replace('"FAIL"', '"PASS"'))  # someone "fixes" the finding
    assert ce.verify_run(run_dir) == ["IAM-03.json: file hash does not match manifest"]

import json

from lab.recovery import recover
from lab.telemetry import normalize


def test_real_sysmon_records_recovered_without_inventing_defender(tmp_path):
    sample = r"C:\Sandbox\sample.ps1"
    timestamp = "2026-10-01T15:00:00Z"
    events = [
        {"event_id": 1, "record_id": 1, "time": timestamp, "data": {"ProcessGuid": "{probe}", "ProcessId": "42", "Image": "powershell.exe", "CommandLine": sample}},
        {"event_id": 13, "record_id": 2, "time": "2026-10-01T15:00:02Z", "data": {"ProcessGuid": "{probe}", "ProcessId": "42", "Image": "powershell.exe", "TargetObject": r"HKCU\Software\SandboxLabProbe", "Details": "benign"}},
    ]
    (tmp_path / "sysmon.jsonl").write_text("\n".join(json.dumps(row) for row in events))
    (tmp_path / "launch.json").write_text(json.dumps({"sample_path": sample, "root_pid": 42, "launch_time": timestamp, "status": "started"}))
    raw = recover(tmp_path)
    assert raw["recovered"]
    dynamic = normalize(raw)
    assert dynamic["counts"]["related_events"] == 2
    assert dynamic["registry"][0]["target"].endswith("SandboxLabProbe")
    assert dynamic["defender"]["status"] == "partial"
    assert dynamic["defender"]["assessment"] != "clean"
    assert dynamic["capabilities"]["combined_export"]["status"] == "partial"


def test_recovery_preserves_independent_defender_receipt(tmp_path):
    (tmp_path / "sysmon.jsonl").write_text(json.dumps({"event_id": 4, "data": {}}))
    receipt = {"status": "completed", "events": [], "detections": [{"id": "real", "threat_name": "test"}]}
    (tmp_path / "defender-state.json").write_text(json.dumps(receipt))
    assert recover(tmp_path)["defender"] == receipt


def test_no_records_or_symlink_does_not_claim_recovery(tmp_path):
    assert recover(tmp_path) == {}
    (tmp_path / "other.jsonl").write_text(json.dumps({"event_id": 13}))
    (tmp_path / "sysmon.jsonl").symlink_to(tmp_path / "other.jsonl")
    assert recover(tmp_path) == {}

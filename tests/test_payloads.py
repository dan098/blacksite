import hashlib
import json
import os
from pathlib import Path

import pytest

from lab.payloads import (
    MANIFEST_NAME,
    MAX_FILE_BYTES,
    MAX_MANIFEST_BYTES,
    MAX_RECORDS,
    MAX_TOTAL_BYTES,
    payload_artifact_candidates,
    read_payloads,
)


ROOT = "{11111111-1111-1111-1111-111111111111}"
CHILD = "{22222222-2222-2222-2222-222222222222}"


def process(guid=ROOT, pid=100, parent="", start="2026-10-02T10:00:00Z"):
    return {"identity": guid, "guid": guid, "pid": pid, "start_time": start,
            "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "identity_source": "sysmon_guid", "parent_identity": parent}


def event_ref(number=11, record=2, time="2026-10-02T10:00:01Z"):
    return {"source": "sysmon", "event_id": number, "record_id": record, "index": record - 1, "time": time}


def record(content=b"Write-Output 'benign stage2'\r\n", index=0, artifact_index=None, **extra):
    artifact_index = index if artifact_index is None else artifact_index
    digest = hashlib.sha256(content).hexdigest()
    return {"index": index, "artifact_index": artifact_index,
            "source_path": r"C:\Users\Quickemu\Downloads\stage2.ps1",
            "source_process": process(), "event_ref": event_ref(),
            "sha256": digest, "size": len(content), "status": "collected",
            "artifact_name": f"payload-{artifact_index:03d}-{digest}.bin", "flags": [],
            "observed_uses": [], **extra}


def manifest(tmp_path, records, **extra):
    data = {"schema_version": 1, "status": "completed", "truncated": False,
            "root_process": process(), "payloads": records, "budgets": {}, **extra}
    (tmp_path / MANIFEST_NAME).write_text(json.dumps(data), encoding="utf-8")
    return data


def put_artifact(tmp_path, item, content=b"Write-Output 'benign stage2'\r\n"):
    (tmp_path / item["artifact_name"]).write_bytes(content)


def test_benign_stage2_and_child_are_private_verified_bins(tmp_path):
    stage = b"Write-Output 'benign stage2'\r\n"
    child = b"Write-Output 'benign child'\r\n"
    parent_item = record(stage, observed_uses=[{
        "process": process(CHILD, 200, ROOT, "2026-10-02T10:00:02Z"),
        "event_ref": event_ref(1, 3, "2026-10-02T10:00:02Z"),
        "association": "command_line_path_reference_not_execution_proof",
    }])
    child_item = record(child, 1, source_path=r"C:\Users\Quickemu\Downloads\child.ps1",
                        source_process=process(CHILD, 200, ROOT, "2026-10-02T10:00:02Z"),
                        event_ref=event_ref(11, 4, "2026-10-02T10:00:03Z"))
    manifest(tmp_path, [parent_item, child_item])
    put_artifact(tmp_path, parent_item, stage)
    put_artifact(tmp_path, child_item, child)

    result = read_payloads(tmp_path)
    assert result["status"] == "completed"
    assert result["artifact_names"] == [parent_item["artifact_name"], child_item["artifact_name"]]
    assert all(name.endswith(".bin") for name in result["artifact_names"])
    assert result["payloads"][1]["source_process"]["parent_identity"] == ROOT
    assert result["payloads"][0]["observed_uses"][0]["process"]["guid"] == CHILD
    assert result["payloads"][0]["event_ref"]["record_id"] == 2
    assert result["trust"] == "untrusted_guest_metadata"
    assert result["budgets"]["verified_bytes"] == len(stage) + len(child)


def test_candidates_are_not_verified_artifacts_until_bytes_arrive(tmp_path):
    item = record()
    manifest(tmp_path, [item])
    assert payload_artifact_candidates(tmp_path) == [item["artifact_name"]]
    result = read_payloads(tmp_path)
    assert not result["artifact_names"]
    assert result["status"] == "partial"
    assert result["payloads"][0]["validation_errors"] == ["artifact_missing"]


@pytest.mark.parametrize("filename", [
    "../escape.bin", "..\\escape.bin", "/tmp/escape.bin", r"C:\escape.bin",
    "nested/payload-000-" + "a" * 64 + ".bin",
    "payload-000-" + "a" * 64 + ".exe", "payload-016-" + "a" * 64 + ".bin",
    "payload-000-" + "A" * 64 + ".bin", "payload-000-" + "a" * 64 + ".bin\x00",
])
def test_arbitrary_artifact_names_never_requested_or_opened(tmp_path, filename):
    manifest(tmp_path, [record(artifact_name=filename)])
    assert payload_artifact_candidates(tmp_path) == []
    result = read_payloads(tmp_path)
    assert result["status"] == "untrusted"
    assert result["artifact_names"] == []
    assert "unsafe_artifact_name" in result["payloads"][0]["validation_errors"]


@pytest.mark.parametrize("source", [
    r"\\server\share\stage2.ps1", r"\\?\C:\stage2.ps1", r"\\.\C:\stage2.ps1",
    r"\Device\HarddiskVolume1\stage2.ps1", r"D:\stage2.ps1", r"C:stage2.ps1",
    r"C:\Downloads\..\stage2.ps1", r"C:\Downloads\.\stage2.ps1", "C:/stage2.ps1",
    r"C:\Downloads\stage2.ps1:stream.ps1", r"C:\Downloads\NUL.ps1", "C:\\Downloads \\stage2.ps1",
    "C:\\Downloads\\COM\u00b9.ps1", r"C:\Downloads\CONIN$.ps1", r"C:\Downloads\CONOUT$.exe",
    r"C:\Downloads\NUL .ps1",
    r"C:\Downloads\stage2.txt",
])
def test_successful_record_with_unsafe_source_path_is_untrusted(tmp_path, source):
    item = record(source_path=source)
    manifest(tmp_path, [item])
    put_artifact(tmp_path, item)
    assert payload_artifact_candidates(tmp_path) == []
    result = read_payloads(tmp_path)
    assert result["status"] == "untrusted"
    assert result["artifact_names"] == []


def test_actual_bytes_sha256_is_recomputed_and_mismatch_visible(tmp_path):
    content = b"Write-Output 'benign stage2'\r\n"
    item = record(content)
    manifest(tmp_path, [item])
    put_artifact(tmp_path, item, content.replace(b"stage2", b"change"))
    result = read_payloads(tmp_path)
    evidence = result["payloads"][0]
    assert result["status"] == "untrusted"
    assert evidence["actual_sha256"] != evidence["sha256"]
    assert "sha256_mismatch" in " ".join(evidence["validation_errors"])
    assert evidence["guest_status"] == "collected"
    assert not result["artifact_names"]


def test_manifest_cannot_rename_a_tampered_hash(tmp_path):
    item = record(sha256="f" * 64)
    manifest(tmp_path, [item])
    assert payload_artifact_candidates(tmp_path) == []
    assert "unsafe_artifact_name" in read_payloads(tmp_path)["payloads"][0]["validation_errors"]


@pytest.mark.parametrize("object_kind", ["symlink", "directory", "fifo", "hardlink"])
def test_artifact_must_be_regular_nonlinked_file(tmp_path, object_kind):
    item = record()
    manifest(tmp_path, [item])
    destination = tmp_path / item["artifact_name"]
    other = tmp_path / "outside"
    other.write_bytes(b"Write-Output 'benign stage2'\r\n")
    if object_kind == "symlink":
        destination.symlink_to(other)
    elif object_kind == "directory":
        destination.mkdir()
    elif object_kind == "fifo":
        os.mkfifo(destination)
    else:
        os.link(other, destination)
    result = read_payloads(tmp_path)
    assert result["status"] == "untrusted"
    assert result["artifact_names"] == []


def test_manifest_symlink_is_rejected(tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"schema_version": 1, "payloads": []}))
    (tmp_path / MANIFEST_NAME).symlink_to(outside)
    assert read_payloads(tmp_path)["status"] == "untrusted"
    assert payload_artifact_candidates(tmp_path) == []


def test_run_directory_or_ancestor_symlink_is_rejected(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    manifest(real, [])
    symlink = tmp_path / "link"
    symlink.symlink_to(real, target_is_directory=True)
    assert read_payloads(symlink)["status"] == "error"
    nested = real / "nested"
    nested.mkdir()
    manifest(nested, [])
    assert read_payloads(symlink / "nested")["status"] == "error"


def test_manifest_size_cap_is_independent_of_claimed_budgets(tmp_path):
    (tmp_path / MANIFEST_NAME).write_bytes(b" " * (MAX_MANIFEST_BYTES + 1))
    assert read_payloads(tmp_path)["status"] == "untrusted"
    assert payload_artifact_candidates(tmp_path) == []


@pytest.mark.parametrize("declared_size", [MAX_FILE_BYTES + 1, -1, True, "10", None])
def test_per_file_manifest_budget_and_size_types(tmp_path, declared_size):
    manifest(tmp_path, [record(size=declared_size)], budgets={"max_file_bytes": 10**20})
    assert payload_artifact_candidates(tmp_path) == []
    assert read_payloads(tmp_path)["status"] == "untrusted"


def test_actual_file_size_is_bounded_before_reading(tmp_path):
    item = record()
    manifest(tmp_path, [item])
    with (tmp_path / item["artifact_name"]).open("wb") as stream:
        stream.truncate(MAX_FILE_BYTES + 1)
    result = read_payloads(tmp_path)
    assert result["status"] == "untrusted"
    assert result["budgets"]["bytes_read"] == 0


def test_actual_size_disagrees_with_manifest(tmp_path):
    item = record()
    manifest(tmp_path, [item])
    put_artifact(tmp_path, item, b"short")
    result = read_payloads(tmp_path)
    assert result["status"] == "untrusted"
    assert "size_mismatch" in " ".join(result["payloads"][0]["validation_errors"])


def test_aggregate_bytes_and_file_count_do_not_use_guest_budget(tmp_path):
    records = [record(index=index, size=MAX_FILE_BYTES) for index in range(5)]
    manifest(tmp_path, records, budgets={"max_total_bytes": 10**20, "max_files": 1000})
    assert len(payload_artifact_candidates(tmp_path)) == MAX_TOTAL_BYTES // MAX_FILE_BYTES
    result = read_payloads(tmp_path)
    assert "total_budget_limit" in result["payloads"][4]["validation_errors"]
    assert result["status"] == "untrusted"
    records = [record(index=index) for index in range(17)]
    manifest(tmp_path, records)
    assert len(payload_artifact_candidates(tmp_path)) == 16
    assert "artifact_index_limit" in read_payloads(tmp_path)["payloads"][16]["validation_errors"]


def test_missing_deleted_unavailable_and_over_limit_preserve_metadata(tmp_path):
    records = [record(index=index, status=status, artifact_index=None, artifact_name=None,
                      sha256=None, size=MAX_FILE_BYTES + 1 if status == "over_limit" else None,
                      flags=["delete_event_observed"] if status == "deleted" else [])
               for index, status in enumerate(["missing", "deleted", "unavailable", "over_limit"])]
    manifest(tmp_path, records, status="partial")
    result = read_payloads(tmp_path)
    assert result["status"] == "partial"
    assert [p["status"] for p in result["payloads"]] == ["missing", "deleted", "unavailable", "over_limit"]
    assert all(p["verification"] == "metadata_only" for p in result["payloads"])
    assert all(p["source_path"].endswith("stage2.ps1") for p in result["payloads"])
    assert result["payloads"][1]["flags"] == ["delete_event_observed"]
    assert not result["artifact_names"]


def test_rejected_unc_metadata_is_retained_but_never_captured(tmp_path):
    item = record(status="rejected", source_path=r"\\server\share\stage2.ps1",
                  artifact_name=None, sha256=None, size=None, flags=["unsafe_source_path"])
    manifest(tmp_path, [item], status="partial")
    evidence = read_payloads(tmp_path)["payloads"][0]
    assert evidence["status"] == "rejected"
    assert evidence["source_path"].startswith("\\\\")
    assert evidence["verification"] == "metadata_only"


@pytest.mark.parametrize("identity", [None, {}, {"pid": 100}, process(start="not-a-time"),
                                      process(guid="", pid=100), {**process(), "identity": CHILD}])
def test_missing_or_inconsistent_source_identity_cannot_claim_success(tmp_path, identity):
    item = record(source_process=identity)
    manifest(tmp_path, [item])
    put_artifact(tmp_path, item)
    result = read_payloads(tmp_path)
    assert result["status"] == "untrusted"
    assert "missing_source_identity" in result["payloads"][0]["validation_errors"]
    assert not result["artifact_names"]


def test_pid_time_identity_and_process_start_preserved(tmp_path):
    source = process(guid="")
    source["identity_source"] = "pid_time"
    source["identity"] = "pid:100:2026-10-02T10:00:00Z:0"
    item = record(index=20, artifact_index=0, source_process=source)
    manifest(tmp_path, [item])
    put_artifact(tmp_path, item)
    result = read_payloads(tmp_path)
    assert result["status"] == "completed"
    assert result["payloads"][0]["source_process"]["identity"] == source["identity"]
    assert result["artifact_names"] == [item["artifact_name"]]


def test_file_create_reference_must_follow_process_creation(tmp_path):
    item = record(source_process=process(start="2026-10-02T10:00:02Z"))
    manifest(tmp_path, [item])
    assert payload_artifact_candidates(tmp_path) == []
    assert "event_before_source_process" in read_payloads(tmp_path)["payloads"][0]["validation_errors"]


def test_non_file_create_event_cannot_claim_payload(tmp_path):
    item = record(event_ref=event_ref(1))
    manifest(tmp_path, [item])
    assert payload_artifact_candidates(tmp_path) == []
    assert "invalid_event_reference" in read_payloads(tmp_path)["payloads"][0]["validation_errors"]


def test_missing_event_record_and_index_cannot_claim_payload(tmp_path):
    item = record(event_ref={**event_ref(), "record_id": None, "index": None})
    manifest(tmp_path, [item])
    assert payload_artifact_candidates(tmp_path) == []
    assert "missing_event_reference" in read_payloads(tmp_path)["payloads"][0]["validation_errors"]


def test_duplicate_names_indices_and_artifact_slots_are_not_registered_twice(tmp_path):
    item = record()
    manifest(tmp_path, [item, dict(item)])
    put_artifact(tmp_path, item)
    result = read_payloads(tmp_path)
    assert result["artifact_names"] == [item["artifact_name"]]
    assert result["status"] == "untrusted"
    assert "duplicate_index" in result["payloads"][1]["validation_errors"]
    assert "duplicate_artifact_index" in result["payloads"][1]["validation_errors"]


@pytest.mark.parametrize("malformed", [None, "not-an-object", 7, [], {"index": []}])
def test_malformed_records_do_not_crash_loader(tmp_path, malformed):
    manifest(tmp_path, [malformed])
    assert read_payloads(tmp_path)["status"] == "untrusted"
    assert payload_artifact_candidates(tmp_path) == []


def test_manifest_record_limit_and_duplicate_json_keys(tmp_path):
    manifest(tmp_path, [None] * (MAX_RECORDS + 1))
    assert read_payloads(tmp_path)["status"] == "untrusted"
    (tmp_path / MANIFEST_NAME).write_text('{"schema_version":1,"schema_version":1,"payloads":[]}')
    assert read_payloads(tmp_path)["status"] == "untrusted"


def test_no_manifest_reports_unavailable_not_empty_success(tmp_path):
    result = read_payloads(tmp_path)
    assert result["status"] == "unavailable"
    assert result["artifact_names"] == []


def test_empty_capture_and_truncated_capture_are_distinct(tmp_path):
    manifest(tmp_path, [])
    assert read_payloads(tmp_path)["status"] == "completed"
    manifest(tmp_path, [], status="partial", truncated=True)
    result = read_payloads(tmp_path)
    assert result["status"] == "partial"
    assert "payload_metadata_truncated" in result["warnings"]


def test_guest_contract_is_guid_and_pid_time_rooted_not_filename_selection():
    source = (Path(__file__).parents[1] / "guest" / "payload_capture.ps1").read_text()
    assert "function Invoke-PayloadCapture" in source
    assert "Explicit unknown GUID never falls back" in source
    assert "$launchPid=Parse-Pid (Field $Launch 'root_pid')" in source
    assert "$launchTime=Parse-Time (Field $Launch 'launch_time')" in source
    assert "if($e.id -ne 11){continue}" in source
    assert "if(-not $p -or -not $p.related){continue}" in source
    assert "end=$null" in source and "function Within-Process" in source
    assert "$Event.index -ge $reuse.index" in source and "start.AddTicks(-1)" not in source
    assert "OPEN_REPARSE_POINT" in source and "GetFinalPathNameByHandle" in source
    assert "SetFileInformationByHandle(Stream.SafeFileHandle,3" in source
    assert "$output.Rename($name)" in source and "[IO.File]::Move" not in source
    assert "Encoding.Unicode.GetBytes(Path.Combine(parentPath,basename))" in source
    assert "Marshal.WriteIntPtr(info,rootOffset,directories" not in source
    assert "payloads.json" in source and "+'.bin'" in source
    assert "Invoke-WebRequest" not in source and "Start-Process" not in source

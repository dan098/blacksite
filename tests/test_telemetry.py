from pathlib import Path

from lab.telemetry import normalize, read_procmon


def event(number, record, time, **data):
    return {"event_id": number, "record_id": record, "time": time, "data": data}


def raw(events, **extra):
    return {
        "sample_path": r"C:\Samples\sample.exe", "root_pid": 100,
        "launch_time": "2026-10-01T10:00:00Z", "start_time": "2026-10-01T09:59:50Z",
        "end_time": "2026-10-01T10:01:00Z", "sysmon": events,
        "defender": {"status": "completed", "events": [], "detections": []}, **extra,
    }


def root():
    return event(1, 1, "2026-10-01T10:00:00Z", ProcessId=100,
                 ProcessGuid="{ROOT}", ParentProcessId=80, ParentProcessGuid="{LAUNCHER}",
                 Image=r"C:\Samples\sample.exe", CommandLine=r"C:\Samples\sample.exe")


def test_pid_reuse_does_not_inherit_sample_identity():
    result = normalize(raw([
        root(),
        event(1, 2, "2026-10-01T10:00:01Z", ProcessId=200, ProcessGuid="{CHILD}",
              ParentProcessId=100, ParentProcessGuid="{ROOT}", Image=r"C:\Windows\System32\cmd.exe"),
        event(5, 3, "2026-10-01T10:00:02Z", ProcessId=200, ProcessGuid="{CHILD}"),
        event(1, 4, "2026-10-01T10:00:04Z", ProcessId=200, ProcessGuid="{REUSED}",
              ParentProcessId=4, ParentProcessGuid="{SYSTEM}", Image=r"C:\Windows\explorer.exe"),
        event(13, 5, "2026-10-01T10:00:05Z", ProcessId=200, ProcessGuid="{REUSED}",
              TargetObject=r"HKCU\Software\NormalApplication\Preference", Details="test"),
        event(11, 6, "2026-10-01T10:00:05Z", ProcessId=200, TargetFilename=r"C:\Users\Quickemu\note.txt"),
    ]))
    by_guid = {p["guid"]: p for p in result["processes"]}
    assert by_guid["{child}"]["related"]
    assert by_guid["{root}"]["children"] == ["{child}"]
    assert not by_guid["{reused}"]["related"]
    assert not result["events"][-1]["related"]
    assert result["events"][-1]["process_guid"] == "{reused}"
    assert len(result["events"]) == 6


def test_unknown_explicit_guid_never_falls_back_to_known_pid():
    result = normalize(raw([root(), event(11, 2, "2026-10-01T10:00:01Z",
                           ProcessId=100, ProcessGuid="{UNKNOWN}", TargetFilename=r"C:\x.txt")]))
    assert not result["events"][1]["related"]
    assert result["events"][1]["raw"]["data"]["ProcessGuid"] == "{UNKNOWN}"


def test_background_noise_is_retained_and_system_image_not_denied():
    result = normalize(raw([
        root(),
        event(1, 2, "2026-10-01T10:00:01Z", ProcessId=201, ProcessGuid="{LOL}",
              ParentProcessGuid="{ROOT}", ParentProcessId=100, Image=r"C:\Windows\System32\powershell.exe"),
        event(13, 3, "2026-10-01T10:00:02Z", ProcessId=201, ProcessGuid="{LOL}",
              Image=r"C:\Windows\System32\powershell.exe",
              TargetObject=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Payload", Details="payload.exe"),
        event(11, 4, "2026-10-01T10:00:03Z", ProcessId=4, ProcessGuid="{SYSTEM}",
              Image="System", TargetFilename=r"C:\Windows\background.log"),
    ]))
    assert len(result["events"]) == 4
    assert result["noise"]["removed_events"] == 0
    assert result["events"][2]["related"]
    assert any(f["rule"] == "persistence_registry" and f["related"] for f in result["findings"])
    assert result["events"][3]["noise"] == "background"


def test_global_unsigned_driver_not_attributed_by_pid_but_never_hidden():
    result = normalize(raw([root(), event(6, 2, "2026-10-01T10:00:02Z", ProcessId=100,
                                         Image="System", ImageLoaded=r"C:\Windows\bad.sys", Signed="false")]))
    driver = result["drivers"][0]
    assert driver["target"].endswith("bad.sys")
    assert not driver["related"]
    assert driver["attribution"] == "unavailable_global"
    finding = next(f for f in result["findings"] if f["rule"] == "unsigned_driver")
    assert finding["severity"] == "high"
    assert finding["evidence_ids"] == ["sysmon:2"]
    assert not finding["related"]


def test_driver_service_delta_is_not_claimed_as_load_or_byovd():
    result = normalize(raw([root()], changes={"services": [{"action": "created",
        "after": {"Name": "TestDriver", "PathName": r"C:\Test\driver.sys", "ServiceType": "Kernel Driver"}}]}))
    assert result["drivers"] == []
    finding = next(f for f in result["findings"] if f["rule"] == "driver_service_delta")
    assert finding["confidence"] == "indicator"
    assert "non prova un caricamento" in finding["rationale"]
    assert not result["changes"]["services"][0]["related"]


def test_benign_file_registry_and_task_changes_do_not_generate_malware_findings():
    result = normalize(raw([
        root(), event(11, 2, "2026-10-01T10:00:01Z", ProcessId=100, ProcessGuid="{ROOT}",
                      TargetFilename=r"C:\Users\Quickemu\hello.txt"),
        event(13, 3, "2026-10-01T10:00:02Z", ProcessId=100, ProcessGuid="{ROOT}",
              TargetObject=r"HKCU\Software\Hello\WindowPosition", Details="42"),
    ], changes={"files": [{"action": "created", "after": {"path": "hello.txt"}}],
                "registry": [{"action": "modified", "path": r"HKCU\Software\Hello"}],
                "tasks": [{"action": "modified", "path": r"\Microsoft\Windows\Maintenance"}],
                "services": []}))
    assert not result["findings"]
    assert result["counts"]["related_events"] == 3
    assert result["defender"]["assessment"] == "no_hit_not_clean"
    assert result["changes"]["files"][0]["attribution"] == "snapshot_delta_not_causality"


def test_global_defender_alert_retained_without_false_sample_causality():
    result = normalize(raw([root()], defender={"status": "partial", "detections": [],
        "events": [event(1116, 5, "2026-10-01T10:00:03Z", ThreatName="Test threat", ProcessName="Unknown")]}))
    assert result["defender"]["assessment"] == "detections_observed"
    assert result["defender"]["status"] == "partial"
    assert any(f["rule"] == "defender_detection" and not f["related"] for f in result["findings"])
    assert len(result["events"]) == 2


def test_frida_nt_chain_is_user_mode_and_matches_enter_leave():
    trace = [
        {"pid": 100, "tid": 1, "time": "2026-10-01T10:00:01Z", "api": "kernel32.dll!CreateFileW",
         "phase": "enter", "call_id": "a", "stack": [{"symbol": "callee"}, {"symbol": "caller"}]},
        {"pid": 100, "tid": 1, "time": "2026-10-01T10:00:01Z", "api": "ntdll.dll!NtCreateFile",
         "phase": "enter", "call_id": "b", "stack": [{"symbol": "Nt"}, {"symbol": "CreateFileW"}]},
        {"pid": 100, "tid": 1, "time": "2026-10-01T10:00:02Z", "api": "ntdll.dll!NtCreateFile",
         "phase": "leave", "call_id": "b", "return_value": "0x0"},
    ]
    result = normalize(raw([root()]), trace)
    assert len(result["api_calls"]) == 3
    assert len(result["call_chains"]) == 2
    nt = result["syscall_chain"][0]
    assert nt["kind"] == "nt_user_mode_entry"
    assert nt["parent_call_id"] == "a"
    assert nt["return_value"] == "0x0"
    assert "non dimostra" in nt["coverage"]
    assert result["call_chains"][0]["frames"][0]["symbol"] == "caller"
    assert all(call["related"] for call in result["api_calls"])


def test_procmon_read_clock_mapping_and_registry_reads(tmp_path: Path):
    path = tmp_path / "procmon.csv"
    path.write_text('"Time of Day","Process Name","PID","Operation","Path","Result","Detail"\n'
                    '"12:00:01.1234567 PM","sample.exe","100","RegQueryValue","HKCU\\Software\\Hello","SUCCESS","Length: 4"\n', encoding="utf-8")
    rows = read_procmon(path)
    result = normalize(raw([root()], procmon=rows,
        procmon_clock={"local_at_start": "2026-10-01T11:59:50+02:00", "offset_minutes": 120},
        baseline={"before": {"registry": [{"path": r"HKCU\Software\Hello"}]}}))
    read = result["registry"][0]
    assert read["source"] == "procmon"
    assert read["related"]
    assert read["time"].startswith("2026-10-01T10:00:01.123456")
    assert read["noise"] == "baseline_read"
    assert read["raw"]["raw_columns"]["Operation"] == "RegQueryValue"
    assert not result["findings"]


def test_procmon_missing_clock_and_caps_are_explicit(tmp_path: Path):
    path = tmp_path / "procmon.csv"
    path.write_text('Time of Day,Process Name,PID,Operation,Path,Result,Detail\n'
                    '10:00:01.1,sample.exe,100,ReadFile,C:\\x,SUCCESS,a\n'
                    '10:00:02.1,sample.exe,100,ReadFile,C:\\x,SUCCESS,b\n', encoding="utf-8")
    rows = read_procmon(path, max_events=1)
    assert rows[-1]["action"] == "truncated"
    result = normalize(raw([root()], procmon=rows))
    read = next(event for event in result["events"] if event["source"] == "procmon" and event["category"] == "file")
    assert not read["related"]
    assert read["attribution"] == "time_unavailable"
    assert result["noise"]["removed_events"] == 0


def test_procmon_midnight_and_pid_reuse_use_utc_window(tmp_path: Path):
    path = tmp_path / "procmon.csv"
    path.write_text('Time of Day,Process Name,PID,Operation,Path,Result,Detail\n'
                    '00:00:01.0,sample.exe,100,ReadFile,C:\\x,SUCCESS,a\n', encoding="utf-8")
    result = normalize({
        "sample_path": r"C:\Samples\sample.exe", "root_pid": 100, "launch_time": "2026-10-01T21:59:55Z",
        "start_time": "2026-10-01T21:59:50Z", "end_time": "2026-10-01T22:00:10Z",
        "sysmon": [event(1, 1, "2026-10-01T21:59:55Z", ProcessId=100, ProcessGuid="{ROOT}", Image=r"C:\Samples\sample.exe")],
        "procmon": read_procmon(path), "procmon_clock": {"local_at_start": "2026-10-01T23:59:50+02:00", "offset_minutes": 120},
    })
    assert result["files"][0]["time"].startswith("2026-10-01T22:00:01")
    assert result["files"][0]["related"]


def test_missing_launch_time_does_not_attribute_recycled_root_pid():
    data = raw([root()])
    data.pop("launch_time")
    result = normalize(data)
    assert not any(p["related"] for p in result["processes"])
    assert result["defender"]["assessment"] != "clean"

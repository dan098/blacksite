import base64
import json
import struct
from pathlib import Path

import pytest

from lab.kernel import (
    IMAGE, MAX_RECORD_BYTES, PERFINFO, PROCESS, STACKWALK, THREAD,
    normalize_kernel, read_kernel,
)


START = "2026-10-02T10:00:00Z"


def record(provider, opcode, second=1, pid=100, tid=101, data=None, **extra):
    return {"schema": "sandbox.kernel.record.v1", "source": "kernel_etw",
            "provider_guid": provider, "opcode": opcode, "event_id": 0,
            "header_pid": pid, "header_tid": tid,
            "time": f"2026-10-02T10:00:{second:02d}Z",
            "timestamp_raw": str(100000 + second * 1000),
            "data": data or {}, **extra}


def enter(second=1, **extra):
    fields = extra.pop("data", {"SysCallAddress": "0xfffff80112345000"})
    return record(PERFINFO, 51, second, data=fields, **extra)


def leave(second=2, **extra):
    return record(PERFINFO, 52, second, data={"SysCallNtStatus": "0xc0000022"}, **extra)


def parents():
    return [{"pid": 100, "guid": "{SAMPLE}", "start_time": START,
             "end_time": None, "related": True, "image": r"C:\Windows\System32\svchost.exe"}]


def report(events, **extra):
    return {"events": events, "receipts": {
        "start": {"status": "recording", "capabilities": {"logging_mode": "memory_ring"}},
        "stop": {"status": "captured"},
        "decode": {"status": "completed", "loss": {"events_lost": 0, "buffers_lost": 0,
                                                       "counter_source": "OpenTraceW.TRACE_LOGFILE_HEADER"}},
    }, "parser": {"max_bytes": 67108864, "max_events": 50000,
                  "partial": False, "truncated": False}, **extra}


def xml_event(provider, opcode, second=1, pid=100, tid=101, **fields):
    data = "".join(f'<Data Name="{name}">{value}</Data>' for name, value in fields.items())
    return (f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            f'<System><Provider Name="Windows Kernel Trace" Guid="{{{provider}}}"/>'
            f'<EventID>0</EventID><Version>2</Version><Opcode>{opcode}</Opcode>'
            f'<TimeCreated SystemTime="2026-10-02T10:00:{second:02d}Z"/>'
            f'<Execution ProcessID="{pid}" ThreadID="{tid}"/></System>'
            f'<EventData>{data}</EventData></Event>')


def write_jsonl(path, records):
    path.write_text("".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")


def test_classic_mof_syscall_enter_exit_are_actual_kernel_records():
    raw = report([enter(), leave()])
    result = normalize_kernel(raw, processes=parents())
    assert result["status"] == "available"
    assert result["counts"]["syscall_enter"] == 1
    assert result["counts"]["syscall_exit"] == 1
    assert result["counts"]["syscall_pairs"] == 1
    call = result["syscall_pairs"][0]
    assert call["syscall_address"] == "0xfffff80112345000"
    assert call["ntstatus"] == "0xc0000022"
    assert call["pid"] == 100 and call["tid"] == 101
    assert call["related"]
    assert call["pairing"] == "observed_same_thread_chronology_not_causality"
    assert not result["coverage"]["full_coverage"]
    assert result["events"][0]["raw"] is raw["events"][0]
    assert result["capabilities"]["symbol_resolution"] == "raw_addresses_only"
    assert "syscall_name" not in call  # An address is not a guessed Nt* symbol.


def test_native_payload_decodes_verified_pointer_width_and_ntstatus():
    address = 0xfffff80112345678
    first = record(PERFINFO, 51, payload_base64=base64.b64encode(struct.pack("<Q", address)).decode(), header_flags=0x40)
    last = record(PERFINFO, 52, 2, payload_base64=base64.b64encode(struct.pack("<I", 0xc0000005)).decode())
    result = normalize_kernel(report([first, last]), processes=parents())
    assert result["events"][0]["syscall_address"] == hex(address)
    assert result["events"][1]["ntstatus"] == "0xc0000005"
    assert result["events"][0]["raw"]["data"] == {}  # Never mutate raw evidence.


def test_unknown_pointer_width_never_guesses_payload_schema():
    first = record(PERFINFO, 51, payload_base64=base64.b64encode(struct.pack("<Q", 0x1234)).decode())
    result = normalize_kernel(report([first]), processes=parents())
    assert result["events"][0]["syscall_address"] is None
    assert result["status"] == "partial"
    assert "syscall_address_missing" in result["events"][0]["decode_gaps"]


def test_stackwalk_payload_subject_identity_not_exporter_header():
    stack_data = struct.pack("<QIIQQ", 101000, 100, 101, 0xfffff80112345678, 0x7ffb12345000)
    stack = record(STACKWALK, 32, 2, pid=4, tid=99,
                   payload_base64=base64.b64encode(stack_data).decode(), header_flags=0x40)
    result = normalize_kernel(report([enter(), stack, leave(3)]), processes=parents())
    observed = result["stacks"][0]
    assert observed["pid"] == 100 and observed["tid"] == 101
    assert observed["header_pid"] == 4 and observed["header_tid"] == 99
    assert observed["stack_addresses"] == ["0xfffff80112345678", "0x7ffb12345000"]
    assert observed["stack_link_status"] == "exact_original_timestamp_pid_tid"
    assert observed["linked_event_ids"] == ["kernel:0"]
    assert result["events"][0]["stack_event_ids"] == ["kernel:1"]
    assert observed["related"]


def test_classic_stack_numbered_fields_preserve_order_and_exact_link_only():
    stack = record(STACKWALK, 32, 2, pid=4, tid=4,
                   data={"EventTimeStamp": "101001", "StackProcess": "0x64", "StackThread": 101,
                         "Stack10": "0xa", "Stack2": "0x2", "Stack1": "0x1"})
    result = normalize_kernel(report([enter(), stack, leave(3)]), processes=parents())
    observed = result["stacks"][0]
    assert observed["stack_addresses"] == ["0x1", "0x2", "0xa"]
    assert observed["stack_link_status"] == "unlinked"  # No nearest-event inference.
    assert "stack_event_ids" not in result["events"][0]


def test_same_timestamp_multiple_candidates_are_ambiguous_stacks():
    stack = record(STACKWALK, 32, 3, data={"EventTimeStamp": "101000", "StackProcess": 100,
                                         "StackThread": 101, "Stack1": "0xffff1234"})
    result = normalize_kernel(report([enter(), enter(), stack]), processes=parents())
    assert result["stacks"][0]["stack_link_status"] == "ambiguous"
    assert len(result["stacks"][0]["linked_event_ids"]) == 2
    assert all("stack_event_ids" not in item for item in result["events"][:2])


def test_user_nt_hooks_and_named_unknown_provider_never_count_as_kernel():
    hook = enter(source="frida_trace", function="NtCreateFile", event_name="SysClEnter")
    unknown = enter(provider_guid="not-a-kernel-provider", event_name="SysClEnter", function="NtCreateFile")
    result = normalize_kernel(report([hook, unknown]), processes=parents())
    assert result["status"] == "unavailable"
    assert result["counts"]["syscall_enter"] == 0
    assert result["counts"]["user_mode_records"] == 1
    assert result["events"][0]["kind"] == "user_mode_record"
    assert result["events"][0]["raw"]["function"] == "NtCreateFile"
    assert not result["capabilities"]["user_mode_hooks_are_kernel"]


def test_recording_and_successful_stop_with_no_calls_are_not_availability():
    result = normalize_kernel(report([record(IMAGE, 10, data={"FileName": "ntoskrnl.exe"})]))
    assert result["status"] == "unavailable"
    assert result["capabilities"]["system_call_enter"] == "not_observed"
    assert result["counts"]["events"] == 1


def test_pid_time_guid_reuse_does_not_inherit_sample_relatedness():
    identities = parents() + [{"pid": 100, "guid": "{REUSED}", "start_time": "2026-10-02T10:00:05Z",
                               "related": False, "end_time": None}]
    result = normalize_kernel(report([enter(), leave(), enter(6), leave(7)]), processes=identities)
    assert [item["related"] for item in result["events"]] == [True, True, False, False]
    assert [item["process_guid"] for item in result["events"]] == ["sample", "sample", "reused", "reused"]
    assert len(result["syscall_pairs"]) == 2
    assert identities[0]["end_time"] is None  # Parent ownership unchanged.


def test_explicit_unknown_guid_never_falls_back_to_known_pid():
    result = normalize_kernel(report([enter(process_guid="{UNKNOWN}")]), processes=parents())
    assert not result["events"][0]["related"]
    assert result["events"][0]["identity_status"] == "unknown_or_outside_explicit_guid"
    assert not result["syscall_pairs"]


def test_thread_lifecycle_links_missing_header_pid_and_guards_recycled_tid():
    thread1 = record(THREAD, 1, 0, pid=4, tid=4, data={"ProcessId": 100, "TThreadId": 101})
    end1 = record(THREAD, 2, 3, pid=4, tid=4, data={"ProcessId": 100, "TThreadId": 101})
    thread2 = record(THREAD, 1, 4, pid=4, tid=4, data={"ProcessId": 200, "TThreadId": 101})
    result = normalize_kernel(report([thread1, enter(pid=0xffffffff), leave(pid=0xffffffff), end1,
                                      thread2, enter(5, pid=0xffffffff), leave(6, pid=0xffffffff)]), processes=parents())
    assert len(result["thread_map"]) == 2
    assert result["events"][1]["pid"] == 100 and result["events"][1]["related"]
    assert result["events"][5]["pid"] == 200 and not result["events"][5]["related"]
    assert result["syscall_pairs"][0]["thread_identity"] != result["syscall_pairs"][1]["thread_identity"]


def test_conflicting_thread_and_header_pid_does_not_attribute_sample():
    thread = record(THREAD, 1, 0, data={"ProcessId": 200, "TThreadId": 101})
    result = normalize_kernel(report([thread, enter()]), processes=parents())
    event = result["events"][1]
    assert not event["related"]
    assert event["identity_status"] == "conflicting_header_and_thread_pid"
    assert result["status"] == "partial"


def test_chronological_pairs_do_not_cross_lifetimes_and_missing_events_are_explicit():
    identities = parents() + [{"pid": 100, "guid": "{REUSED}", "start_time": "2026-10-02T10:00:05Z",
                               "related": False, "end_time": None}]
    result = normalize_kernel(report([leave(7), enter(1), enter(2), leave(3), enter(4)]), processes=identities)
    assert len(result["syscall_pairs"]) == 1
    assert result["syscall_pairs"][0]["enter_time"].endswith("02Z")
    kinds = {item["kind"] for item in result["coverage"]["gaps"]}
    assert {"missing_exit_or_nested_call", "missing_enter", "missing_exit_at_capture_boundary"} <= kinds
    assert result["status"] == "partial"


def test_kernel_process_thread_and_image_maps_remain_global_raw_evidence():
    proc = record(PROCESS, 1, 0, pid=4, tid=4, data={"ProcessId": 100, "ImageFileName": "sample.exe",
                                                   "UniqueProcessKey": "0xffff01234"})
    image = record(IMAGE, 10, 1, data={"ProcessId": 100, "ImageBase": "0x7ff00000", "ImageSize": "4096",
                                     "FileName": r"C:\Windows\System32\ntdll.dll"})
    result = normalize_kernel(report([proc, image, enter(2), leave(3)]))
    assert result["process_map"][0]["unique_process_key"] == "0xffff01234"
    assert result["image_map"][0]["base_address"] == "0x7ff00000"
    assert result["image_map"][0]["size"] == 4096
    assert not any(item["related"] for item in result["events"])
    assert result["events"][2]["identity_status"] == "kernel_pid_time_not_linked_to_sample"
    assert len(result["syscall_pairs"]) == 1


def test_system_image_is_related_only_by_parent_identity_not_name_denylist():
    result = normalize_kernel(report([enter(), leave()]), processes=parents())
    assert all(item["related"] for item in result["events"])
    unknown = normalize_kernel(report([enter(pid=300)]), processes=parents())
    assert not unknown["events"][0]["related"]
    assert unknown["events"][0]["identity_status"] == "unknown_identity"


def test_timezone_missing_never_owns_process_identity():
    result = normalize_kernel(report([enter(time="2026-10-02T10:00:01")]), processes=parents())
    assert not result["events"][0]["related"]
    assert result["events"][0]["identity_status"] == "unknown_identity"


def test_loss_and_unknown_counters_are_reported_not_invented():
    raw = report([enter(), leave()])
    raw["receipts"]["decode"]["loss"]["events_lost"] = 17
    result = normalize_kernel(raw, processes=parents())
    assert result["status"] == "partial"
    assert result["coverage"]["loss"]["events_lost"] == 17
    assert any(item["kind"] == "etl_event_or_buffer_loss" for item in result["coverage"]["gaps"])
    raw["receipts"]["decode"].pop("loss")
    result = normalize_kernel(raw, processes=parents())
    assert result["coverage"]["loss"]["events_lost"] is None
    assert result["status"] == "partial"


def test_unsupported_start_retains_etl_without_false_success(tmp_path):
    (tmp_path / "kernel_start.json").write_text(json.dumps({"status": "unavailable", "error": "SystemCall unsupported"}))
    (tmp_path / "kernel.etl").write_bytes(b"retained evidence")
    raw = read_kernel(tmp_path)
    result = normalize_kernel(raw)
    assert result["status"] == "unavailable"
    assert result["receipts"]["start"]["error"] == "SystemCall unsupported"
    assert result["artifacts"]["kernel.etl"]["retained"]
    assert (tmp_path / "kernel.etl").read_bytes() == b"retained evidence"


def test_jsonl_event_and_byte_caps_are_explicit_and_raw_file_unchanged(tmp_path):
    path = tmp_path / "kernel_events.jsonl"
    write_jsonl(path, [enter(), leave(), enter(3)])
    original = path.read_bytes()
    raw = read_kernel(path, max_events=2)
    assert len(raw["events"]) == 2
    assert raw["parser"]["truncated"]
    assert "event_cap" in raw["parser"]["errors"]
    result = normalize_kernel(raw, processes=parents())
    assert result["status"] == "partial"
    assert result["coverage"]["truncated"]
    assert path.read_bytes() == original
    limited = read_kernel(path, max_bytes=32)
    assert limited["parser"]["bytes_read"] <= 33
    assert limited["parser"]["truncated"]
    assert not limited["events"]


def test_malformed_json_keeps_prior_and_following_valid_records(tmp_path):
    path = tmp_path / "kernel_events.jsonl"
    path.write_text(json.dumps(enter()) + "\n{invalid}\n" + json.dumps(leave()) + "\n")
    raw = read_kernel(path)
    assert len(raw["events"]) == 2
    assert raw["status"] == "partial"
    assert "invalid_json_record" in raw["warnings"][0]


def test_large_or_deep_json_record_is_rejected_with_bounded_work(tmp_path):
    path = tmp_path / "kernel_events.jsonl"
    path.write_bytes(b'{"payload":"' + b"x" * MAX_RECORD_BYTES + b'"}\n')
    raw = read_kernel(path)
    assert not raw["events"] and raw["parser"]["truncated"]
    assert "record_byte_cap" in raw["warnings"]
    path.write_text('{"nested":' + "[" * 30 + "0" + "]" * 30 + "}\n")
    raw = read_kernel(path)
    assert not raw["events"]
    assert "record_structure_cap" in raw["warnings"][0]


def test_classic_tracerpt_xml_enter_exit_schema_streaming(tmp_path):
    path = tmp_path / "kernel_events.xml"
    path.write_text("<Events>" + xml_event(PERFINFO, 51, SysCallAddress="0xfffff80112345000") +
                    xml_event(PERFINFO, 52, 2, SysCallNtStatus="0xc0000022") + "</Events>")
    raw = read_kernel(path)
    result = normalize_kernel(raw, processes=parents())
    assert len(raw["events"]) == 2
    assert raw["events"][0]["provider_guid"] == "{" + PERFINFO + "}"
    assert "SysCallAddress" in raw["events"][0]["raw_xml"]
    assert result["counts"]["syscall_pairs"] == 1
    assert result["events"][0]["syscall_address"] == "0xfffff80112345000"
    assert result["status"] == "partial"  # Standalone XML has no fabricated loss/start receipts.


def test_utf16_tracerpt_xml_is_streamed_and_stack_schema_decoded(tmp_path):
    path = tmp_path / "kernel_events.xml"
    text = '<?xml version="1.0" encoding="UTF-16"?><Events>' + xml_event(
        STACKWALK, 32, pid=4, tid=4, EventTimeStamp="101000", StackProcess="100", StackThread="101",
        Stack1="0xfffff80100000000", Stack2="0x7ffb00000000") + "</Events>"
    path.write_bytes(text.encode("utf-16"))
    raw = read_kernel(path)
    assert len(raw["events"]) == 1
    result = normalize_kernel(raw, processes=parents())
    assert result["counts"]["stackwalk"] == 1
    assert result["stacks"][0]["pid"] == 100
    assert result["stacks"][0]["stack_addresses"] == ["0xfffff80100000000", "0x7ffb00000000"]
    assert result["status"] == "unavailable"  # Stacks alone do not prove syscall observation.


def test_rendering_info_names_do_not_overwrite_native_xml_opcode(tmp_path):
    path = tmp_path / "kernel_events.xml"
    text = xml_event(PERFINFO, 51, SysCallAddress="0x1234").replace(
        "</Event>", "<RenderingInfo><Opcode>SysClEnter</Opcode><Task>PerfInfo</Task></RenderingInfo></Event>")
    path.write_text("<Events>" + text + "</Events>")
    raw = read_kernel(path)
    assert raw["events"][0]["opcode"] == "51"
    assert raw["events"][0]["opcode_name"] == "SysClEnter"
    assert normalize_kernel(raw)["counts"]["syscall_enter"] == 1


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16"])
def test_xml_dtd_entity_bombs_are_rejected_before_parsing(tmp_path, encoding):
    path = tmp_path / "kernel_events.xml"
    bomb = '<!DOCTYPE Events [<!ENTITY x "aaaa"><!ENTITY y "&x;&x;&x;&x;">]><Events>&y;</Events>'
    path.write_bytes(bomb.encode(encoding))
    raw = read_kernel(path)
    assert not raw["events"]
    assert "unsafe_xml_dtd_entity_or_encoding" in raw["warnings"]
    assert raw["status"] == "unavailable"


def test_malformed_xml_preserves_accepted_records(tmp_path):
    path = tmp_path / "kernel_events.xml"
    # First chunk finishes a valid event; the following malformed chunk must not
    # discard evidence already accepted by the streaming parser.
    path.write_text("<Events>" + xml_event(PERFINFO, 51, SysCallAddress="0x1234") +
                    " " * 20000 + "<Event><System></Event></Events>")
    raw = read_kernel(path)
    assert len(raw["events"]) == 1
    assert raw["status"] == "partial"
    assert raw["events"][0]["data"]["SysCallAddress"] == "0x1234"


def test_xml_depth_and_record_caps_are_explicit(tmp_path):
    path = tmp_path / "kernel_events.xml"
    path.write_text("<Events>" + "<x>" * 35 + "</x>" * 35 + "</Events>")
    raw = read_kernel(path)
    assert "xml_depth_cap" in raw["warnings"]
    path.write_text("<Events><Event><EventData><Data>" + "x" * (MAX_RECORD_BYTES + 32768) +
                    "</Data></EventData></Event></Events>")
    raw = read_kernel(path)
    assert raw["parser"]["truncated"]
    assert "xml_record_byte_cap" in raw["warnings"]


def test_xml_event_cap_keeps_first_raw_record(tmp_path):
    path = tmp_path / "kernel_events.xml"
    path.write_text("<Events>" + xml_event(PERFINFO, 51, SysCallAddress="0x1234") +
                    xml_event(PERFINFO, 52, 2, SysCallNtStatus="0") + "</Events>")
    raw = read_kernel(path, max_events=1)
    assert len(raw["events"]) == 1
    assert raw["parser"]["truncated"]
    assert "event_cap" in raw["warnings"]


def test_hostile_envelopes_and_counts_do_not_raise_or_claim_kernel():
    malicious = enter(mode={"nested": True}, layer=["user"], data=None,
                      timestamp_raw="9" * 1000, header_pid={"bad": 1})
    result = normalize_kernel(report([malicious], parser={"max_events": "bad", "max_bytes": None}))
    assert result["coverage"]["max_events"] == 50000
    assert result["events"][0]["pid"] is None
    assert result["status"] == "partial"


def test_zero_perf_header_pid_is_resolved_only_from_verified_thread():
    thread = record(THREAD, 1, 0, data={"ProcessId": 100, "TThreadId": 101})
    result = normalize_kernel(report([thread, enter(pid=0), leave(pid=0)]), processes=parents())
    assert result["events"][1]["pid"] == 100
    assert result["events"][1]["pid_basis"] == "kernel_thread_lifecycle"
    assert result["events"][1]["related"]
    missing = normalize_kernel(report([enter(pid=0)]), processes=parents())
    assert missing["events"][0]["pid"] is None
    assert not missing["events"][0]["related"]


def test_calls_after_known_thread_end_do_not_reuse_old_thread_identity():
    thread = record(THREAD, 1, 0, data={"ProcessId": 100, "TThreadId": 101})
    end = record(THREAD, 2, 2, data={"ProcessId": 100, "TThreadId": 101})
    result = normalize_kernel(report([thread, enter(), end, leave(3)]), processes=parents())
    assert not result["events"][3]["related"]
    assert result["events"][3]["identity_status"] == "unknown_thread_lifetime"
    assert not result["syscall_pairs"]


def test_raw_timestamp_disambiguates_filetime_precision_ties():
    exit_event = leave(time="2026-10-02T10:00:01.0000001Z", timestamp_raw="200")
    enter_event = enter(time="2026-10-02T10:00:01.0000000Z", timestamp_raw="100")
    result = normalize_kernel(report([exit_event, enter_event]), processes=parents())
    assert len(result["syscall_pairs"]) == 1
    assert result["syscall_pairs"][0]["enter_id"] == "kernel:1"
    assert result["syscall_pairs"][0]["exit_id"] == "kernel:0"


def test_signed_ntstatus_is_unsigned_bit_pattern_not_a_guessed_verdict():
    exit_event = record(PERFINFO, 52, 2, data={"SysCallNtStatus": "-1073741790"})
    result = normalize_kernel(report([enter(), exit_event]), processes=parents())
    assert result["syscall_pairs"][0]["ntstatus"] == "0xc0000022"


def test_native_zero_loss_never_hides_measured_wpr_status_loss():
    raw = report([enter(), leave()])
    raw["receipts"]["status"] = {"loss": {"events_lost": 13, "buffers_lost": 2,
                                          "counter_source": "wpr_status_english_labels"}}
    raw["receipts"]["stop"]["loss"] = raw["receipts"]["status"]["loss"]
    result = normalize_kernel(raw, processes=parents())
    assert result["coverage"]["loss"]["events_lost"] == 13
    assert result["coverage"]["loss"]["buffers_lost"] == 2
    assert len(result["coverage"]["loss"]["measurements"]) == 3
    assert result["coverage"]["loss"]["aggregation"] == "maximum_not_sum_same_capture"
    assert result["status"] == "partial"


def test_profile_and_guest_lifecycle_contract_is_memory_only_and_strict():
    guest = Path(__file__).resolve().parents[1] / "guest"
    profile = (guest / "kernel.wprp").read_text()
    script = (guest / "kernel_trace.ps1").read_text()
    decoder = (guest / "kernel_decode.cs").read_text()
    assert '<Keyword Value="SystemCall" Strict="true"' in profile
    assert '<Stack Value="SystemCallEnter"' in profile
    assert '<Stack Value="SystemCallExit"' in profile
    assert 'LoggingMode="Memory"' in profile
    assert '<Buffers Value="128"' in profile and '<BufferSize Value="1024"' in profile
    assert "@('-start',($profile+'!SandboxKernel'))" in script
    assert "@('-stop',$etl,'-skipPdbGen')" in script
    assert script.index("$stop=Run-Wpr") < script.index("Add-Type -Path $decoder")
    assert "sandbox.kernel.command.v1" in script
    assert "Set-MpPreference" not in script and "bcdedit" not in script
    assert "Size=448" in decoder and "Size=112" in decoder
    assert "DateTime.FromFileTimeUtc" in decoder
    assert "maxEvents > 100000" in decoder and "maxBytes > 134217728" in decoder
    assert "Mode=0x10000000U" in decoder  # PROCESS_TRACE_MODE_EVENT_RECORD, not 0x100.


def test_missing_classic_context_uses_only_exact_unique_stack_subject():
    first = enter(pid=0xffffffff, tid=0xffffffff, processor=0)
    last = leave(pid=0xffffffff, tid=0xffffffff, processor=0)
    stacks = [record(STACKWALK, 32, second, pid=4, tid=4, processor=0,
                     data={"EventTimeStamp": str(100000 + second * 1000),
                           "StackProcess": 100, "StackThread": 101, "Stack": ["0xffff1234"]})
              for second in (1, 2)]
    result = normalize_kernel(report([first, last, *stacks]), processes=parents())
    assert result["counts"]["syscall_pairs"] == 1
    assert result["syscall_pairs"][0]["related"]
    assert result["events"][0]["pid_basis"] == "exact_native_timestamp_unique_stack_subject"
    assert result["events"][0]["header_pid"] is None
    assert first["header_pid"] == 0xffffffff  # Raw evidence unchanged.


@pytest.mark.parametrize("change", ["timestamp", "processor", "collision", "subject", "user_mode"])
def test_missing_context_never_uses_approximate_or_ambiguous_stack(change):
    first = enter(pid=0xffffffff, tid=0xffffffff, processor=0)
    stack = record(STACKWALK, 32, 1, processor=0,
                   data={"EventTimeStamp": "101000", "StackProcess": 100,
                         "StackThread": 101, "Stack": ["0xffff1234"]})
    events = [first, stack]
    if change == "timestamp":
        stack["data"]["EventTimeStamp"] = "101001"
    elif change == "processor":
        stack["processor"] = 1
    elif change == "collision":
        events.append(enter(pid=200, tid=201, processor=0))
    elif change == "subject":
        events.append(record(STACKWALK, 32, 1, processor=0,
                             data={"EventTimeStamp": "101000", "StackProcess": 200,
                                   "StackThread": 201, "Stack": ["0xffff4567"]}))
    else:
        stack["source"] = "frida_trace"
    result = normalize_kernel(report(events), processes=parents())
    assert result["events"][0]["pid"] is None and result["events"][0]["tid"] is None
    assert not result["events"][0]["related"]


def test_conflicting_exact_stack_subject_never_inherits_sample_identity():
    first = enter(processor=0)
    stack = record(STACKWALK, 32, 1, processor=0,
                   data={"EventTimeStamp": "101000", "StackProcess": 200,
                         "StackThread": 201, "Stack": ["0xffff1234"]})
    result = normalize_kernel(report([first, stack]), processes=parents())
    assert result["events"][0]["identity_status"] == "conflicting_exact_stack_subject"
    assert not result["events"][0]["related"]
    assert result["status"] == "partial"


def test_guest_priority_index_is_bounded_and_does_not_force_relatedness():
    guest = Path(__file__).resolve().parents[1] / "guest"
    decoder = (guest / "kernel_decode.cs").read_text()
    script = (guest / "kernel_trace.ps1").read_text()
    assert "MaxScanEvents = 4000000" in decoder
    assert "MaxSelectedTimestamps = 250000" in decoder
    assert "pid_and_exact_stack_timestamp_priority_not_attribution" in decoder
    assert "omitted_background_records" in decoder
    assert "selected.Length > 256" in decoder
    assert "$MaxBytes,$selectionPids)" in script
    assert "ParentProcessGuid" in script and "-MaxEvents 5000" in script
    raw = enter(index_selection="pid_or_exact_stack_timestamp_candidate_not_attribution", header_pid=200)
    assert not normalize_kernel(report([raw]), processes=parents())["events"][0]["related"]

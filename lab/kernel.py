"""Bounded Microsoft kernel ETW evidence; never relabel Nt* user hooks as kernel calls.

The guest keeps its original ETL. This index preserves accepted decoded raw
records, reports decoding/loss gaps, and only links sample identity using parent
GUID/PID-time evidence. It is not a full-coverage or malware-cleanliness claim.
"""
from __future__ import annotations

import base64
import codecs
import json
import re
import struct
import xml.etree.ElementTree as ET
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

MAX_BYTES = 64 * 1024 * 1024
MAX_EVENTS = 50000
MAX_RECORD_BYTES = 512 * 1024
PERFINFO = "ce1dbfb4-137e-4da6-87b0-3f59aa102cbc"
STACKWALK = "def2fe46-7bd6-4b80-bd94-f57fe20d0ce3"
PROCESS = "3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c"
THREAD = "3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c"
IMAGE = "2cb15d1d-5fc1-11d2-abe1-00a0c911f518"
FILEIO = "90cbdc39-4a3e-11d1-84f4-0000f80464e3"
REGISTRY = "ae53722e-c863-11d2-8659-00c04fa321a1"
_RECEIPTS = {"start": "kernel_start.json", "status": "kernel_status.json",
             "stop": "kernel_stop.json", "decode": "kernel_decode.json",
             "error_start": "kernel_error_start.json", "error_stop": "kernel_error_stop.json"}


def _integer(value: Any, *, maximum: int = (1 << 64) - 1) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and len(value) <= 64:
        text = value.strip()
        try:
            if re.fullmatch(r"[-+]?\d+", text):
                number = int(text, 10)
            elif re.fullmatch(r"0[xX][0-9a-fA-F]+", text):
                number = int(text, 16)
            else:
                return None
        except ValueError:
            return None
    else:
        return None
    return number if 0 <= number <= maximum else None


def _pid(value: Any) -> int | None:
    number = _integer(value, maximum=0xffffffff)
    return number if number != 0xffffffff else None


def _address(value: Any) -> str | None:
    number = _integer(value)
    if number is None and isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{1,16}", value.strip()):
        number = int(value.strip(), 16)
    return f"0x{number:x}" if number is not None else None


def _guid(value: Any) -> str:
    return str(value or "").strip().strip("{}").casefold()


def _time(value: Any) -> float | None:
    if not isinstance(value, str) or len(value) > 128 or not value.strip():
        return None
    try:
        when = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        if when.tzinfo is None:
            return None  # A guest-local clock cannot safely own process identity.
        return when.timestamp()
    except (ValueError, OverflowError, OSError):
        return None


def _field(data: dict, *names: str, default: Any = None) -> Any:
    lowered = {str(key).casefold(): value for key, value in data.items()}
    for name in names:
        if name.casefold() in lowered:
            return lowered[name.casefold()]
    return default


def _bounded_object(value: Any) -> bool:
    """A byte-bounded JSON document can still contain hostile nesting/field counts."""
    pending = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > 4096 or depth > 24:
            return False
        if isinstance(item, str) and len(item) > 131072:
            return False
        if isinstance(item, dict):
            if len(item) > 256 or any(not isinstance(key, str) or len(key) > 512 for key in item):
                return False
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            if len(item) > 1024:
                return False
            pending.extend((child, depth + 1) for child in item)
        elif isinstance(item, float):
            # NaN/Infinity are not valid telemetry JSON.
            if not (-float("inf") < item < float("inf")):
                return False
    return True


def _problem(stats: dict, detail: str) -> None:
    stats["partial"] = True
    if len(stats["errors"]) < 32:
        stats["errors"].append(detail[:256])


def _read_jsonl(path: Path, max_bytes: int, max_events: int, stats: dict) -> list[dict]:
    events = []
    scanned = 0
    with path.open("rb") as stream:
        while True:
            if scanned >= max_events:
                if stream.read(1):
                    stats["truncated"] = True
                    _problem(stats, "event_cap")
                break
            remaining = max_bytes - stats["bytes_read"]
            if remaining <= 0:
                if stream.read(1):
                    stats["truncated"] = True
                    _problem(stats, "byte_cap")
                break
            line = stream.readline(min(MAX_RECORD_BYTES + 1, remaining + 1))
            if not line:
                break
            stats["bytes_read"] += len(line)
            if len(line) > remaining or len(line) > MAX_RECORD_BYTES:
                stats["truncated"] = True
                _problem(stats, "byte_cap" if len(line) > remaining else "record_byte_cap")
                break
            if not line.strip():
                continue
            scanned += 1
            try:
                item = json.loads(line)
                if not isinstance(item, dict) or not _bounded_object(item):
                    _problem(stats, f"record_structure_cap:{scanned}")
                    continue
                events.append(item)
            except (ValueError, UnicodeError, RecursionError) as error:
                _problem(stats, f"invalid_json_record:{scanned}:{type(error).__name__}")
    stats["records_scanned"] = scanned
    return events


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _xml_record(element: ET.Element) -> dict:
    result: dict[str, Any] = {"schema": "sandbox.kernel.xml-record.v1", "source": "kernel_etw", "data": {}}
    for count, node in enumerate(element.iter()):
        if count > 4096:
            raise ValueError("xml_node_count_cap")
        name = _local(node.tag)
        if len(node.text or "") > 131072 or len(node.attrib) > 32:
            raise ValueError("xml_field_cap")
        if name == "Provider":
            result["provider_guid"] = node.attrib.get("Guid", "")
            result["provider_name"] = node.attrib.get("Name", "")
        elif name in {"EventID", "Opcode", "Task", "Version"}:
            if _integer(node.text) is not None:
                result[{"EventID": "event_id", "Opcode": "opcode", "Task": "task", "Version": "version"}[name]] = node.text or ""
            else:
                result[name.casefold() + "_name"] = node.text or ""
            if node.attrib.get("Name"):
                result[name.casefold() + "_name"] = node.attrib["Name"]
        elif name == "TimeCreated":
            result["time"] = node.attrib.get("SystemTime", "")
        elif name == "Execution":
            result["header_pid"] = node.attrib.get("ProcessID")
            result["header_tid"] = node.attrib.get("ThreadID")
        elif name == "Data":
            if len(result["data"]) >= 256:
                raise ValueError("xml_field_count_cap")
            key = node.attrib.get("Name", f"Data{len(result['data'])}")
            if len(key) > 512:
                raise ValueError("xml_field_name_cap")
            result["data"][key] = node.text or ""
    result["raw_xml"] = ET.tostring(element, encoding="unicode")
    if len(result["raw_xml"].encode("utf-8")) > MAX_RECORD_BYTES:
        raise ValueError("xml_record_byte_cap")
    return result


def _read_xml(path: Path, max_bytes: int, max_events: int, stats: dict) -> list[dict]:
    events = []
    stats["accepted_events"] = events
    parser = ET.XMLPullParser(events=("start", "end"))
    stack: list[ET.Element] = []
    active: ET.Element | None = None
    record_start = 0
    scanner = ""
    decoder = None
    stopped = False
    with path.open("rb") as stream:
        while not stopped:
            remaining = max_bytes - stats["bytes_read"]
            chunk = stream.read(min(16384, max(1, remaining + 1)))
            if not chunk:
                break
            before = stats["bytes_read"]
            stats["bytes_read"] += len(chunk)
            if len(chunk) > remaining:
                stats["truncated"] = True
                _problem(stats, "byte_cap")
                break
            if active is not None and stats["bytes_read"] - record_start > MAX_RECORD_BYTES:
                stats["truncated"] = True
                _problem(stats, "xml_record_byte_cap")
                break
            if decoder is None:
                encoding = "utf-16" if chunk.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
                decoder = codecs.getincrementaldecoder(encoding)(errors="strict")
            text = decoder.decode(chunk)
            # Check before feeding Expat; DTD/entity expansion is never permitted.
            scan = (scanner + text).casefold()
            if "<!doctype" in scan or "<!entity" in scan or "\x00" in text:
                _problem(stats, "unsafe_xml_dtd_entity_or_encoding")
                break
            scanner = scan[-64:]
            parser.feed(text)
            for kind, element in parser.read_events():
                if kind == "start":
                    stack.append(element)
                    if len(stack) > 32:
                        _problem(stats, "xml_depth_cap")
                        stopped = True
                        break
                    if _local(element.tag) == "Event":
                        if active is not None:
                            _problem(stats, "nested_xml_event")
                            stopped = True
                            break
                        active = element
                        record_start = before
                else:
                    if element is active:
                        if len(events) >= max_events:
                            stats["truncated"] = True
                            _problem(stats, "event_cap")
                            stopped = True
                            break
                        events.append(_xml_record(element))
                        active = None
                        if len(stack) > 1:
                            stack[-2].remove(element)
                        element.clear()
                    elif active is None:
                        if len(stack) > 1:
                            stack[-2].remove(element)
                        element.clear()
                    stack.pop()
        if not stats["partial"] and not stopped:
            if decoder is not None:
                parser.feed(decoder.decode(b"", final=True))
            parser.close()
    stats["records_scanned"] = len(events)
    return events


def read_kernel(path: Path | str, *, max_bytes: int = MAX_BYTES, max_events: int = MAX_EVENTS) -> dict:
    """Read a run directory, JSONL/XML artifact or ETL path without decoding on Linux.

    Parsing is streaming and hard-capped (ceiling 128 MiB/100k records). ETL stays
    on disk even if the decoder/parser is absent, unsupported, or partial.
    """
    max_bytes = max(1, min(int(max_bytes), 128 * 1024 * 1024))
    max_events = max(1, min(int(max_events), 100000))
    target = Path(path)
    run_dir = target if target.is_dir() else target.parent
    stats = {"bytes_read": 0, "records_scanned": 0, "max_bytes": max_bytes,
             "max_events": max_events, "truncated": False, "partial": False, "errors": []}
    receipts: dict[str, Any] = {}
    for key, name in _RECEIPTS.items():
        receipt = run_dir / name
        if receipt.is_file():
            try:
                with receipt.open("rb") as stream:
                    raw = stream.read(2 * 1024 * 1024 + 1)
                if len(raw) > 2 * 1024 * 1024:
                    raise ValueError("receipt_byte_cap")
                item = json.loads(raw)
                if not isinstance(item, dict) or not _bounded_object(item):
                    raise ValueError("receipt_structure_cap")
                receipts[key] = item
            except (OSError, ValueError, RecursionError) as error:
                _problem(stats, f"receipt:{name}:{type(error).__name__}")
    command_path = run_dir / "kernel_commands.jsonl"
    if command_path.is_file():
        command_stats = {"bytes_read": 0, "errors": [], "partial": False, "truncated": False}
        try:
            receipts["commands"] = _read_jsonl(command_path, 1024 * 1024, 16, command_stats)
            if command_stats["partial"]:
                _problem(stats, "command_receipts_partial")
        except OSError as error:
            _problem(stats, f"command_receipts:{type(error).__name__}")
    artifacts = {}
    for name in ("kernel.etl", "kernel_events.jsonl", "kernel_events.xml", "kernel.xml", *_RECEIPTS.values(), "kernel_commands.jsonl"):
        artifact = run_dir / name
        try:
            if artifact.is_file():
                artifacts[name] = {"path": str(artifact), "bytes": artifact.stat().st_size, "retained": True}
        except OSError:
            _problem(stats, f"artifact_stat:{name}")
    if target.is_dir() or target.suffix.casefold() == ".etl":
        candidates = [run_dir / name for name in ("kernel_events.jsonl", "kernel_events.xml", "kernel.xml")]
        target = next((candidate for candidate in candidates if candidate.is_file()), candidates[0])
    events = []
    try:
        if target.is_file():
            if target.suffix.casefold() == ".xml":
                events = _read_xml(target, max_bytes, max_events, stats)
            elif target.suffix.casefold() in {".jsonl", ".ndjson", ".json"}:
                events = _read_jsonl(target, max_bytes, max_events, stats)
            else:
                _problem(stats, "unsupported_decoded_artifact_format")
        else:
            _problem(stats, "decoded_artifact_missing_etl_retained_if_present")
    except (OSError, ValueError, UnicodeError, ET.ParseError, RecursionError) as error:
        # A streaming XML parse can fail after earlier records. Keep those records
        # by recording into stats during iteration (JSONL already handles each row).
        events = stats.pop("accepted_events", events)
        _problem(stats, f"decoder_artifact:{type(error).__name__}:{error}")
    stats.pop("accepted_events", None)
    return {"schema": "sandbox.kernel.raw.v1", "source": "microsoft_kernel_etw",
            "status": "partial" if events and stats["partial"] else "captured" if events else "unavailable",
            "events": events, "receipts": receipts, "artifacts": artifacts, "parser": stats,
            "warnings": list(stats["errors"])}


def _data(raw: dict) -> dict:
    value = raw.get("data", raw.get("event_data", raw.get("details", {})))
    return value if isinstance(value, dict) else {}


def _classic_payload(raw: dict, provider: str, opcode: int | None, data: dict) -> dict:
    """Decode only documented classic payloads with verified pointer width."""
    encoded = raw.get("payload_base64")
    if not isinstance(encoded, str) or len(encoded) > 87380:
        return data
    try:
        payload = base64.b64decode(encoded, validate=True)
    except ValueError:
        return data
    flags = _integer(raw.get("header_flags")) or 0
    width = 4 if flags & 0x20 else 8 if flags & 0x40 else _integer(raw.get("pointer_size"))
    values = dict(data)
    if provider == PERFINFO and opcode == 51 and width in {4, 8} and len(payload) == width:
        values["SysCallAddress"] = hex(int.from_bytes(payload, "little"))
    elif provider == PERFINFO and opcode == 52 and len(payload) == 4:
        values["SysCallNtStatus"] = hex(int.from_bytes(payload, "little"))
    elif provider == STACKWALK and opcode == 32 and width in {4, 8} and len(payload) >= 16 and (len(payload) - 16) % width == 0 and (len(payload) - 16) // width <= 192:
        timestamp, pid, tid = struct.unpack_from("<QII", payload)
        values.update(EventTimeStamp=str(timestamp), StackProcess=pid, StackThread=tid,
                      Stack=[hex(int.from_bytes(payload[index:index + width], "little"))
                             for index in range(16, len(payload), width)])
    return values


def _normalize_event(raw: dict, index: int) -> dict:
    data = _data(raw)
    provider = raw.get("provider_guid", raw.get("provider", ""))
    if isinstance(provider, dict):
        provider = provider.get("Guid", provider.get("guid", ""))
    provider = _guid(provider)
    opcode = _integer(raw.get("opcode"), maximum=255)
    name = str(raw.get("event_name", raw.get("opcode_name", ""))).casefold()
    source = str(raw.get("source", "kernel_etw")).casefold()
    user_mode = (source.startswith(("frida", "api_")) or "hook" in source
                 or source in {"user_mode", "user-mode", "api"}
                 or str(raw.get("mode", "")).casefold() in {"user", "user_mode"}
                 or str(raw.get("layer", "")).casefold() in {"user", "user_mode"})
    pid = _pid(raw.get("header_pid", raw.get("pid")))
    tid = _pid(raw.get("header_tid", raw.get("tid")))
    kind = "user_mode_record" if user_mode else "kernel_other"
    syscall_address = None
    ntstatus = None
    stack = []
    missing = []
    if not user_mode:
        data = _classic_payload(raw, provider, opcode, data)
        if provider == PERFINFO and (opcode == 51 or opcode is None and name in {"sysclenter", "syscallenter"}):
            kind = "syscall_enter"
            syscall_address = _address(_field(data, "SysCallAddress", "SystemCallAddress"))
            if syscall_address is None:
                missing.append("syscall_address_missing")
        elif provider == PERFINFO and (opcode == 52 or opcode is None and name in {"sysclexit", "syscallexit"}):
            kind = "syscall_exit"
            value = _field(data, "SysCallNtStatus", "NtStatus", "Status")
            status = _integer(value, maximum=0xffffffff)
            if isinstance(value, int) and -(1 << 31) <= value < 0:
                status = value & 0xffffffff
            elif isinstance(value, str) and re.fullmatch(r"-[0-9]{1,10}", value.strip()):
                signed = int(value.strip())
                if -(1 << 31) <= signed < 0:
                    status = signed & 0xffffffff
            ntstatus = f"0x{status:08x}" if status is not None else None
            if ntstatus is None:
                missing.append("ntstatus_missing")
        elif provider == STACKWALK and (opcode == 32 or opcode is None and name == "stack"):
            kind = "stackwalk"
            pid = _pid(_field(data, "StackProcess", "StackProcessId"))
            tid = _pid(_field(data, "StackThread", "StackThreadId"))
            values = _field(data, "Stack", "StackAddresses", default=[])
            if not isinstance(values, list):
                values = re.split(r"[\s,;]+", str(values).strip()) if values else []
            if not values:
                values = [value for key, value in sorted(data.items(), key=lambda item: int(re.sub(r"\D", "", item[0]) or "0"))
                          if re.fullmatch(r"Stack\d+", key, flags=re.IGNORECASE)]
            stack = [_address(value) for value in values[:192]]
            stack = [value for value in stack if value is not None]
            if not stack:
                missing.append("stack_addresses_missing")
            if len(values) > 192:
                missing.append("stack_depth_cap")
        elif provider == PROCESS:
            kind = {1: "process_start", 2: "process_end", 3: "process_rundown_start", 4: "process_rundown_end"}.get(opcode, "process_other")
            pid = _pid(_field(data, "ProcessId", "PID", default=pid))
        elif provider == THREAD:
            kind = {1: "thread_start", 2: "thread_end", 3: "thread_rundown_start", 4: "thread_rundown_end"}.get(opcode, "thread_other")
            pid = _pid(_field(data, "ProcessId", "PID", default=pid))
            tid = _pid(_field(data, "TThreadId", "ThreadId", "TID", default=tid))
        elif provider == IMAGE:
            kind = {10: "image_load", 2: "image_unload", 3: "image_rundown_start", 4: "image_rundown_end"}.get(opcode, "image_other")
            pid = _pid(_field(data, "ProcessId", default=pid))
        elif provider == FILEIO:
            kind = "file_io"
        elif provider == REGISTRY:
            kind = "registry"
    if kind in {"syscall_enter", "syscall_exit"}:
        # Classic perf headers can omit process context (zero/all-ones). Only a
        # verified TID lifetime may replace that missing context.
        if pid == 0:
            pid = None
        if tid == 0:
            tid = None
    return {"id": f"kernel:{index}", "kind": kind, "source": "user_mode" if user_mode else "kernel_etw",
            "provider_guid": provider, "opcode": opcode, "pid": pid, "tid": tid,
            "header_pid": _pid(raw.get("header_pid", raw.get("pid"))),
            "header_tid": _pid(raw.get("header_tid", raw.get("tid"))),
            "time": raw.get("time", raw.get("timestamp", "")), "timestamp_raw": _integer(raw.get("timestamp_raw")),
            "stack_event_timestamp_raw": _integer(_field(data, "EventTimeStamp")) if kind == "stackwalk" else None,
            "syscall_address": syscall_address, "ntstatus": ntstatus, "stack_addresses": stack,
            "process_guid": _guid(raw.get("process_guid", _field(data, "ProcessGuid"))),
            "related": False, "identity_status": "unknown", "thread_identity": None,
            "decode_gaps": missing, "raw": raw}


def _recover_syscall_context(events: list[dict], gaps: list[dict]) -> None:
    """Classic syscall headers may have no PID/TID; use exact native stack evidence.

    No nearest timestamp, current-thread table or executable-name inference.
    A timestamp collision, conflicting subject or CPU mismatch stays unassigned.
    """
    native = defaultdict(list)
    stacks = defaultdict(list)
    for event in events:
        if event["source"] != "kernel_etw":
            continue
        if event["kind"] == "stackwalk":
            if event["stack_event_timestamp_raw"] is not None:
                stacks[event["stack_event_timestamp_raw"]].append(event)
        elif event["timestamp_raw"] is not None:
            native[event["timestamp_raw"]].append(event)
    for stamp, candidates in native.items():
        if len(candidates) != 1:
            continue
        event = candidates[0]
        if event["kind"] not in {"syscall_enter", "syscall_exit"} or not stacks.get(stamp):
            continue
        processor = event["raw"].get("processor")
        matching = [stack for stack in stacks[stamp]
                    if processor is None or stack["raw"].get("processor") == processor]
        subjects = {(stack["pid"], stack["tid"]) for stack in matching
                    if stack["pid"] is not None and stack["tid"] is not None}
        if len(subjects) != 1:
            continue
        pid, tid = next(iter(subjects))
        if event["pid"] not in {None, pid} or event["tid"] not in {None, tid}:
            gaps.append({"kind": "syscall_stack_subject_conflict", "event_id": event["id"], "severity": "partial"})
            event["context_conflict"] = True
            event["identity_status"] = "conflicting_exact_stack_subject"
            continue
        if event["pid"] is None or event["tid"] is None:
            event["pid"], event["tid"] = pid, tid
            event["pid_basis"] = "exact_native_timestamp_unique_stack_subject"
            event["context_stack_ids"] = [stack["id"] for stack in matching if (stack["pid"], stack["tid"]) == (pid, tid)]


def _sort_time(event: dict) -> tuple:
    when = _time(event["time"])
    raw = event["timestamp_raw"]
    ordinal = int(event["id"].rsplit(":", 1)[-1])
    return (0, when, raw or 0, ordinal) if when is not None else (1, raw or 0, 0, ordinal)


def _lifetimes(events: list[dict], prefix: str, key: str) -> list[dict]:
    result = []
    active: dict[int, dict] = {}
    for event in sorted(events, key=_sort_time):
        number = event.get(key)
        if number is None or not event["kind"].startswith(prefix + "_"):
            continue
        if event["kind"] == prefix + "_start":
            previous = active.get(number)
            if previous:
                previous["end_time"] = event["time"]
                previous["end_raw"] = event["timestamp_raw"]
                previous["end_reason"] = "identifier_reuse"
            item = {"id": event["id"], "pid": event["pid"], "tid": event["tid"],
                    "start_time": event["time"], "end_time": None,
                    "start_raw": event["timestamp_raw"], "end_raw": None,
                    "evidence_ids": [event["id"]], "identity_source": "kernel_etw_lifecycle"}
            if prefix == "process":
                data = _data(event["raw"])
                item["image"] = _field(data, "ImageFileName", "ImageName", "Image", default="")
                item["unique_process_key"] = _field(data, "UniqueProcessKey", "ProcessKey")
            result.append(item)
            active[number] = item
        elif event["kind"] == prefix + "_end":
            item = active.get(number)
            if item and (prefix != "thread" or event["pid"] in {None, item["pid"]}):
                item["end_time"] = event["time"]
                item["end_raw"] = event["timestamp_raw"]
                item["evidence_ids"].append(event["id"])
                active.pop(number)
    return result


def _in_interval(event: dict, identity: dict) -> bool:
    raw = event["timestamp_raw"]
    begin_raw = _integer(identity.get("start_raw"))
    end_raw = _integer(identity.get("end_raw"))
    if raw is not None and begin_raw is not None:
        return begin_raw <= raw and (end_raw is None or raw < end_raw)
    when = _time(event["time"])
    start = _time(identity.get("start_time"))
    end = _time(identity.get("end_time"))
    return when is not None and start is not None and start <= when and (end is None or when < end)


def _history_index(histories: dict) -> dict:
    result = {}
    for number, history in histories.items():
        clocks = {}
        for basis, getter in (("utc", lambda item: _time(item.get("start_time"))),
                              ("raw", lambda item: _integer(item.get("start_raw")))):
            entries = [(getter(item), index, item) for index, item in enumerate(history) if getter(item) is not None]
            entries.sort(key=lambda entry: (entry[0], entry[1]))
            clocks[basis] = ([entry[0] for entry in entries], [entry[2] for entry in entries])
        result[number] = clocks
    return result


def _select_history(event: dict, number: int | None, index: dict) -> list[dict]:
    clocks = index.get(number, {})
    for basis, when in (("raw", event["timestamp_raw"]), ("utc", _time(event["time"]))):
        starts, identities = clocks.get(basis, ([], []))
        if when is None or not starts:
            continue
        end = bisect_right(starts, when)
        if not end:
            continue
        begin = bisect_left(starts, starts[end - 1])
        return [item for item in identities[begin:end] if _in_interval(event, item)]
    return []


def normalize_kernel(report: dict, *, processes: list[dict] | dict | None = None, max_events: int = MAX_EVENTS) -> dict:
    """Normalize a read_kernel report and parent telemetry's process identity list.

    Parent processes have pid, guid, start_time, end_time and related. Explicit
    unknown GUIDs never fall back to PID; PID reuse is bounded by the next start.
    TID-only kernel records use verified thread lifecycle intervals, not a current
    process table or denylisted executable names.
    """
    report = report if isinstance(report, dict) else {}
    records = report.get("events", []) if isinstance(report, dict) else []
    records = records if isinstance(records, list) else []
    cap = max(1, min(int(max_events), 100000))
    events = [_normalize_event(raw, index) for index, raw in enumerate(records[:cap]) if isinstance(raw, dict) and _bounded_object(raw)]
    receipts = report.get("receipts", {}) if isinstance(report.get("receipts"), dict) else {}
    parser = report.get("parser", {}) if isinstance(report.get("parser"), dict) else {}
    warnings = [str(value)[:512] for value in report.get("warnings", [])[:64]] if isinstance(report.get("warnings"), list) else []
    gaps = []
    if len(records) > cap or len(events) != min(len(records), cap):
        gaps.append({"kind": "normalization_record_cap_or_invalid", "severity": "partial"})
    _recover_syscall_context(events, gaps)
    process_map = _lifetimes(events, "process", "pid")
    thread_map = _lifetimes(events, "thread", "tid")
    threads_by_tid = defaultdict(list)
    kernel_by_pid = defaultdict(list)
    for thread in thread_map:
        threads_by_tid[thread["tid"]].append(thread)
    for process in process_map:
        kernel_by_pid[process["pid"]].append(process)
    if isinstance(processes, dict):
        parent_values = list(processes.values())[:100000]
    elif isinstance(processes, list):
        parent_values = processes[:100000]
    else:
        parent_values = []
    parents = [dict(value) for value in parent_values if isinstance(value, dict)]
    parents_by_pid = defaultdict(list)
    parents_by_guid = {}
    for process in parents:
        process["pid"] = _pid(process.get("pid"))
        process["guid"] = _guid(process.get("guid", process.get("process_guid")))
        if process["guid"]:
            parents_by_guid[process["guid"]] = process
        if process["pid"] is not None and _time(process.get("start_time")) is not None:
            parents_by_pid[process["pid"]].append(process)
    for history in parents_by_pid.values():
        history.sort(key=lambda process: _time(process["start_time"]))
        for index, process in enumerate(history[:-1]):
            next_start = _time(history[index + 1]["start_time"])
            if _time(process.get("end_time")) is None or _time(process["end_time"]) > next_start:
                process["end_time"] = history[index + 1]["start_time"]
    thread_index = _history_index(threads_by_tid)
    kernel_index = _history_index(kernel_by_pid)
    parent_index = _history_index(parents_by_pid)
    for event in events:
        if event["source"] != "kernel_etw":
            event["identity_status"] = "user_mode_not_kernel"
            continue
        if event.get("context_conflict"):
            continue
        thread_candidates = _select_history(event, event["tid"], thread_index)
        thread = thread_candidates[0] if len(thread_candidates) == 1 else None
        if not thread and event["tid"] in threads_by_tid and event["kind"] in {"syscall_enter", "syscall_exit"}:
            event["identity_status"] = "unknown_thread_lifetime"
            gaps.append({"kind": "thread_lifetime_not_resolved", "event_id": event["id"], "severity": "partial"})
            continue
        if thread:
            event["thread_identity"] = thread["id"]
            if event["pid"] is None:
                event["pid"] = thread["pid"]
                event["pid_basis"] = "kernel_thread_lifecycle"
            elif thread["pid"] is not None and event["pid"] != thread["pid"]:
                event["identity_status"] = "conflicting_header_and_thread_pid"
                gaps.append({"kind": "identity_conflict", "event_id": event["id"], "severity": "partial"})
                continue
        explicit_guid = event["process_guid"]
        if explicit_guid:
            process = parents_by_guid.get(explicit_guid)
            candidates = [process] if process and process.get("pid") == event["pid"] and _in_interval(event, process) else []
            if not candidates:
                event["identity_status"] = "unknown_or_outside_explicit_guid"
                continue
        else:
            candidates = _select_history(event, event["pid"], parent_index)
        if len(candidates) == 1:
            process = candidates[0]
            event["process_guid"] = process["guid"]
            event["related"] = bool(process.get("related"))
            event["identity_status"] = "parent_guid_pid_time" if explicit_guid else "parent_pid_time"
            event["process_identity"] = process["guid"] or f"parent:{process['pid']}:{process['start_time']}"
        else:
            kernel_candidates = _select_history(event, event["pid"], kernel_index)
            if len(kernel_candidates) == 1:
                event["process_identity"] = kernel_candidates[0]["id"]
                event["identity_status"] = "kernel_pid_time_not_linked_to_sample"
            else:
                event["identity_status"] = "unknown_identity"
    image_map = []
    for event in events:
        if event["kind"].startswith("image_"):
            data = _data(event["raw"])
            image_map.append({"event_id": event["id"], "kind": event["kind"], "pid": event["pid"],
                              "time": event["time"], "timestamp_raw": event["timestamp_raw"],
                              "image": _field(data, "FileName", "ImageFileName", "ImageName", default=""),
                              "base_address": _address(_field(data, "ImageBase", "BaseAddress")),
                              "size": _integer(_field(data, "ImageSize", "Size")),
                              "checksum": _field(data, "ImageChecksum", "Checksum"),
                              "symbol_resolution": "raw_addresses_only"})
    # Exact native original timestamp + subject PID/TID is the only stack link.
    # No nearest-neighbour timing guess and no merging into a full causal stack.
    native_events = defaultdict(list)
    for event in events:
        if event["kind"] not in {"stackwalk", "user_mode_record"} and event["timestamp_raw"] is not None:
            native_events[(event["timestamp_raw"], event["pid"], event["tid"])].append(event)
    stacks = []
    for event in events:
        if event["kind"] != "stackwalk":
            continue
        key = (event["stack_event_timestamp_raw"], event["pid"], event["tid"])
        matches = native_events.get(key, []) if key[0] is not None and key[1] is not None and key[2] is not None else []
        event["linked_event_ids"] = [match["id"] for match in matches]
        event["stack_link_status"] = "exact_original_timestamp_pid_tid" if len(matches) == 1 else "ambiguous" if matches else "unlinked"
        if len(matches) == 1:
            match = matches[0]
            if event["process_guid"] and event["process_guid"] != match["process_guid"]:
                event["identity_status"] = "unknown_or_conflicting_stack_guid"
                event["related"] = False
            else:
                event["related"] = match["related"]
                event["process_guid"] = match["process_guid"]
                event["identity_status"] = match["identity_status"]
            match.setdefault("stack_event_ids", []).append(event["id"])
        stacks.append(event)
    pairs = []
    pending = {}
    for event in sorted(events, key=_sort_time):
        if event["kind"] not in {"syscall_enter", "syscall_exit"}:
            continue
        if event["decode_gaps"]:
            gaps.append({"kind": "syscall_decode_gap", "event_id": event["id"], "detail": event["decode_gaps"], "severity": "partial"})
        identity = event["thread_identity"] or event.get("process_identity")
        if event["pid"] is None or event["tid"] is None or identity is None or (_time(event["time"]) is None and event["timestamp_raw"] is None):
            gaps.append({"kind": "syscall_unpaired_identity_or_time_unknown", "event_id": event["id"], "severity": "partial"})
            continue
        key = (event["pid"], event["tid"], identity)
        if event["kind"] == "syscall_enter":
            previous = pending.get(key)
            if previous:
                gaps.append({"kind": "missing_exit_or_nested_call", "event_id": previous["id"], "next_enter_id": event["id"], "severity": "partial"})
            pending[key] = event
        else:
            enter = pending.pop(key, None)
            if not enter:
                gaps.append({"kind": "missing_enter", "event_id": event["id"], "severity": "partial"})
                continue
            pairs.append({"enter_id": enter["id"], "exit_id": event["id"], "pid": event["pid"], "tid": event["tid"],
                          "process_guid": enter["process_guid"], "thread_identity": enter["thread_identity"],
                          "enter_time": enter["time"], "exit_time": event["time"],
                          "syscall_address": enter["syscall_address"], "ntstatus": event["ntstatus"],
                          "related": enter["related"] and event["related"], "complete": True,
                          "pairing": "observed_same_thread_chronology_not_causality",
                          "integrity": "loss_or_decode_gaps_possible"})
    for event in pending.values():
        gaps.append({"kind": "missing_exit_at_capture_boundary", "event_id": event["id"], "severity": "partial"})
    decode = receipts.get("decode", {}) if isinstance(receipts.get("decode"), dict) else {}
    status_receipt = receipts.get("status", {}) if isinstance(receipts.get("status"), dict) else {}
    stop_receipt = receipts.get("stop", {}) if isinstance(receipts.get("stop"), dict) else {}
    measurements = []
    for name, receipt in (("decode", decode), ("status", status_receipt), ("stop", stop_receipt)):
        counters = receipt.get("loss")
        if isinstance(counters, dict):
            measurements.append({"receipt": name, "events_lost": _integer(counters.get("events_lost")),
                                 "buffers_lost": _integer(counters.get("buffers_lost")),
                                 "counter_source": str(counters.get("counter_source", "unknown"))[:256]})
    loss = {"counter_source": measurements[0]["counter_source"] if measurements else "unknown",
            "measurements": measurements, "aggregation": "maximum_not_sum_same_capture"}
    for field in ("events_lost", "buffers_lost"):
        measured = [item[field] for item in measurements if item[field] is not None]
        loss[field] = max(measured) if measured else None
    if loss["events_lost"] is None or loss["buffers_lost"] is None:
        gaps.append({"kind": "loss_counters_unknown", "severity": "partial"})
    if (loss["events_lost"] or 0) > 0 or (loss["buffers_lost"] or 0) > 0:
        gaps.append({"kind": "etl_event_or_buffer_loss", "loss": loss, "severity": "partial"})
    truncated = bool(parser.get("truncated") or decode.get("truncated") or len(records) > cap)
    if truncated:
        gaps.append({"kind": "decoded_index_truncated_raw_etl_retained", "severity": "partial"})
    if parser.get("partial"):
        errors = parser.get("errors", [])
        gaps.append({"kind": "host_parser_partial", "detail": errors[:32] if isinstance(errors, list) else str(errors)[:512], "severity": "partial"})
    for name in ("start", "stop", "decode"):
        receipt = receipts.get(name)
        good = {"start": {"recording"}, "stop": {"captured", "completed"}, "decode": {"completed"}}[name]
        if not isinstance(receipt, dict) or str(receipt.get("status")) not in good:
            gaps.append({"kind": f"{name}_receipt_missing_or_partial", "status": receipt.get("status") if isinstance(receipt, dict) else "missing", "severity": "partial"})
    capabilities = receipts.get("start", {}).get("capabilities", {}) if isinstance(receipts.get("start"), dict) else {}
    if isinstance(capabilities, dict) and capabilities.get("logging_mode") == "memory_ring":
        gaps.append({"kind": "memory_ring_history_not_guaranteed", "severity": "information", "overwritten_events": None})
    counts = Counter(event["kind"] for event in events)
    observed = counts["syscall_enter"] + counts["syscall_exit"] > 0
    partial = any(gap.get("severity") == "partial" for gap in gaps)
    status = "partial" if observed and partial else "available" if observed else "unavailable"
    if not observed:
        warnings.append("No actual Microsoft kernel SysCallEnter/Exit events observed; WPR recording or Nt* user hooks do not establish availability.")
    warnings.append("Kernel ETW is bounded, system-wide evidence, not 100% syscall coverage or a full causal-stack reconstruction.")
    if any(event["identity_status"].startswith("unknown") for event in events):
        warnings.append("Unknown process identities remain unassigned; no image-name denylist or blanket sample attribution is applied.")
    return {"schema": "sandbox.kernel.normalized.v1", "source": "microsoft_kernel_etw", "status": status,
            "events": events, "syscall_pairs": pairs, "stacks": stacks,
            "process_map": process_map, "thread_map": thread_map, "image_map": image_map,
            "counts": {"events": len(events), "syscall_enter": counts["syscall_enter"], "syscall_exit": counts["syscall_exit"],
                       "stackwalk": counts["stackwalk"], "syscall_pairs": len(pairs),
                       "related_events": sum(event["related"] for event in events),
                       "unknown_identity": sum(event["identity_status"].startswith("unknown") for event in events),
                       "user_mode_records": counts["user_mode_record"]},
            "coverage": {"max_bytes": _integer(parser.get("max_bytes")) or MAX_BYTES,
                         "max_events": min(_integer(parser.get("max_events")) or cap, cap),
                         "truncated": truncated, "loss": loss, "gaps": gaps[:100000], "full_coverage": False,
                         "stacks": "observed_kernel_stackwalk_not_full_causal_stack"},
            "capabilities": {"system_call_enter": "observed" if counts["syscall_enter"] else "not_observed",
                             "system_call_exit": "observed" if counts["syscall_exit"] else "not_observed",
                             "kernel_stackwalk": "observed" if stacks else "not_observed",
                             "symbol_resolution": "raw_addresses_only", "user_mode_hooks_are_kernel": False},
            "receipts": receipts, "artifacts": report.get("artifacts", {}), "warnings": warnings}


# Matching the existing lab.telemetry.normalize naming is convenient for callers.
normalize = normalize_kernel

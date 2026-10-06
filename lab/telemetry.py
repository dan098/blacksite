"""Normalize bounded guest evidence; absence of a sensor or a hit is not a verdict."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import csv
import io
from pathlib import Path
import re
import threading
from typing import Any

_EVENT_TYPES = {
    1: ("process", "create"), 2: ("file", "creation_time_changed"),
    3: ("network", "connect"), 4: ("sensor", "service_state"),
    5: ("process", "terminate"), 6: ("driver", "load"),
    7: ("image", "load"), 8: ("process", "remote_thread"),
    9: ("file", "raw_access"), 10: ("process", "access"),
    11: ("file", "create"), 12: ("registry", "object_change"),
    13: ("registry", "value_set"), 14: ("registry", "rename"),
    15: ("file", "stream_create"), 16: ("sensor", "configuration_changed"),
    17: ("pipe", "create"), 18: ("pipe", "connect"),
    19: ("persistence", "wmi_filter"), 20: ("persistence", "wmi_consumer"),
    21: ("persistence", "wmi_binding"), 22: ("network", "dns_query"),
    23: ("file", "delete_archived"), 24: ("clipboard", "change"),
    25: ("process", "tampering"), 26: ("file", "delete"),
    27: ("file", "executable_blocked"), 28: ("file", "shredding_blocked"),
    29: ("file", "executable_detected"), 255: ("sensor", "error"),
}
_PERSISTENCE = re.compile(
    r"\\(?:run|runonce)(?:\\|$)|\\winlogon\\(?:shell|userinit)$|"
    r"\\image file execution options\\|\\silentprocessexit\\|"
    r"\\currentcontrolset\\services\\[^\\]+\\(?:imagepath|start|type)$|"
    r"\\(shellserviceobjectdelayload|appinit_dlls)(?:\\|$)", re.I,
)


def _pid(value: Any) -> int | None:
    try:
        return int(str(value), 16 if str(value).lower().startswith("0x") else 10)
    except (TypeError, ValueError):
        return None


def _guid(value: Any) -> str:
    return str(value or "").strip().lower()


def _path(value: Any) -> str:
    return str(value or "").replace("/", "\\").strip().strip('"').casefold()


def _time(value: Any) -> float | None:
    if value is None or value == "":
        return None
    if isinstance(value, (float, int)):
        # Frida records milliseconds; other sensors use epoch seconds or ISO UTC.
        return float(value) / 1000 if value > 100_000_000_000 else float(value)
    try:
        text = str(value).strip().replace("Z", "+00:00")
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except (ValueError, OverflowError):
        return None


def _list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _field(data: dict, *names: str, default: Any = None) -> Any:
    for name in names:
        if name in data:
            return data[name]
    folded = {str(k).casefold(): v for k, v in data.items()}
    for name in names:
        if name.casefold() in folded:
            return folded[name.casefold()]
    return default


def _event(raw: dict, index: int, source: str = "sysmon") -> dict:
    data = raw.get("data", raw.get("event_data", raw.get("details", {})))
    if not isinstance(data, dict):
        data = {"raw_data": data}
    number = _pid(raw.get("event_id", raw.get("EventId", raw.get("EventID"))))
    if source == "sysmon":
        category, action = _EVENT_TYPES.get(number, ("other", "event"))
    else:
        category, action = raw.get("category", "security"), raw.get("action", "event")
    guid = _guid(_field(data, "ProcessGuid", "SourceProcessGUID", default=raw.get("process_guid")))
    pid = _pid(_field(data, "ProcessId", "SourceProcessId", default=raw.get("pid")))
    image = _field(data, "Image", "SourceImage", "ImageLoaded", default=raw.get("image", ""))
    target = _field(data, "TargetFilename", "TargetObject", "ImageLoaded", "DestinationIp",
                    "QueryName", "TargetImage", "PipeName", "Destination", default=raw.get("target", ""))
    return {
        "id": str(raw.get("id") or f"{source}:{raw.get('record_id', raw.get('RecordId', index))}"),
        "time": raw.get("time", raw.get("TimeCreated", _field(data, "UtcTime", default=""))),
        "category": category, "action": action, "event_id": number,
        "pid": pid, "process_guid": guid, "image": str(image or ""),
        "target": str(target or ""), "details": data, "related": False,
        "source": source, "raw": raw,
    }


_CSV_LOCK = threading.Lock()


def read_procmon(path: Path, max_events: int = 25000) -> list[dict]:
    """Read at most 64 MiB/25,000 CSV rows; preserve raw columns and uncertainty.

    Time-of-day is not an identity timestamp until normalize has the guest clock.
    CSV errors/caps become explicit sensor events instead of pretending success.
    """
    max_events = max(0, min(int(max_events), 25000))
    limit = 64 * 1024 * 1024
    rows: list[dict] = []
    try:
        with path.open("rb") as stream:
            payload = stream.read(limit + 1)
        capped_bytes = len(payload) > limit
        payload = payload[:limit]
        if capped_bytes:
            # Do not parse a possibly half-written final record.
            payload = payload[:payload.rfind(b"\n") + 1]
        encoding = "utf-16" if payload.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
        text = payload.decode(encoding, errors="strict")
        with _CSV_LOCK:
            previous_limit = csv.field_size_limit()
            csv.field_size_limit(262144)
            try:
                first_line = text.split("\n", 1)[0]
                delimiter = "\t" if "\t" in first_line else ","
                reader = csv.DictReader(io.StringIO(text, newline=""), delimiter=delimiter)
                fields = set(reader.fieldnames or [])
                if not {"PID", "Operation", "Path"}.issubset(fields):
                    raise ValueError("Intestazioni CSV Procmon mancanti/non supportate")
                for index, row in enumerate(reader):
                    if index >= max_events:
                        rows.append({"source": "procmon", "category": "sensor", "action": "truncated",
                                     "id": "procmon:cap", "data": {"status": "partial", "event_cap": max_events}})
                        break
                    operation = str(row.get("Operation") or "")
                    if operation.startswith("Reg"):
                        category = "registry"
                    elif operation.startswith(("TCP", "UDP")):
                        category = "network"
                    elif operation.startswith(("Process", "Thread")):
                        category = "process"
                    elif operation == "Load Image":
                        category = "image"
                    else:
                        category = "file"
                    result = str(row.get("Result") or "")
                    outcome = "completed" if result == "SUCCESS" else (
                        "denied" if "DENIED" in result or "BLOCKED" in result else "observed_result")
                    rows.append({"id": f"procmon:{index}", "source": "procmon", "category": category,
                                 "action": operation, "pid": _pid(row.get("PID")), "time": "",
                                 "time_of_day": row.get("Time of Day", ""),
                                 "date_time": row.get("Date & Time", row.get("Time", "")),
                                 "image": row.get("Process Name", ""), "target": row.get("Path", ""),
                                 "data": {**row, "outcome": outcome}, "raw_columns": row})
            finally:
                csv.field_size_limit(previous_limit)
        if capped_bytes:
            rows.append({"source": "procmon", "category": "sensor", "action": "truncated",
                         "id": "procmon:byte-cap", "data": {"status": "partial", "max_bytes": limit}})
    except (OSError, ValueError, UnicodeError, csv.Error) as exc:
        rows.append({"source": "procmon", "category": "sensor", "action": "error",
                     "id": "procmon:read-error", "data": {"status": "error", "detail": str(exc)[:2048]}})
    return rows


def _procmon_time(item: dict, raw: dict) -> str:
    clock = raw.get("procmon_clock") if isinstance(raw.get("procmon_clock"), dict) else {}
    local_start = clock.get("local_at_start")
    offset = clock.get("offset_minutes")
    window_start, window_end = _time(raw.get("start_time")), _time(raw.get("end_time"))
    explicit = item.get("time") or item.get("date_time")
    if explicit:
        try:
            parsed = datetime.fromisoformat(str(explicit).replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                if offset is None:
                    return ""
                parsed = parsed.replace(tzinfo=timezone(timedelta(minutes=float(offset))))
            if window_start is None or window_end is None or not window_start - 1 <= parsed.timestamp() <= window_end + 1:
                return ""
            return parsed.astimezone(timezone.utc).isoformat()
        except (TypeError, ValueError, OverflowError):
            pass
    text = str(item.get("time_of_day") or "").strip()
    match = re.fullmatch(r"(\d{1,2}):(\d{2}):(\d{2})(?:[.,](\d{1,7}))?\s*(AM|PM)?", text, re.I)
    if not match or not local_start or offset is None or window_start is None or window_end is None:
        return ""
    try:
        date = datetime.fromisoformat(str(local_start).replace("Z", "+00:00")).date()
        hour, minute, second = (int(match.group(n)) for n in (1, 2, 3))
        marker = match.group(5)
        if marker:
            if not 1 <= hour <= 12:
                return ""
            hour = hour % 12 + (12 if marker.upper() == "PM" else 0)
        fraction = int((match.group(4) or "").ljust(6, "0")[:6])
        tz = timezone(timedelta(minutes=float(offset)))
        base = datetime(date.year, date.month, date.day, hour, minute, second, fraction, tzinfo=tz)
        candidates = [base + timedelta(days=shift) for shift in (-1, 0, 1)]
        candidates = [stamp for stamp in candidates if window_start - 1 <= stamp.timestamp() <= window_end + 1]
        return candidates[0].astimezone(timezone.utc).isoformat() if len(candidates) == 1 else ""
    except (ValueError, OverflowError, TypeError):
        return ""


def normalize(raw: dict, api_events: list | None = None) -> dict:
    """Keep every supplied raw event. GUID/time identity, not PID alone, owns ancestry.

    Global driver/security/delta evidence remains visible even when attribution is
    unavailable. Noise labels are presentation hints only; no event is discarded.
    """
    warnings = list(_list(raw.get("warnings")))
    launch = raw.get("launch") if isinstance(raw.get("launch"), dict) else {}
    root_pid = _pid(raw.get("root_pid", launch.get("root_pid")))
    launch_time = _time(raw.get("launch_time", launch.get("launch_time")))
    sample_path = _path(raw.get("sample_path", launch.get("sample_path")))
    root_guid = _guid(raw.get("root_guid", launch.get("root_guid")))
    source_events = raw.get("sysmon", raw.get("events", [])) or []
    if isinstance(source_events, dict):
        source_events = source_events.get("events", [])
    source_events = _list(source_events)
    events = [_event(item, n) for n, item in enumerate(source_events) if isinstance(item, dict)]
    defender_raw = raw.get("defender") or {}
    if not isinstance(defender_raw, dict):
        defender_raw = {"events": _list(defender_raw)}
    defender_events = [_event(item, n, "defender")
                       for n, item in enumerate(_list(defender_raw.get("events"))) if isinstance(item, dict)]
    events.extend(defender_events)
    for n, item in enumerate(_list(raw.get("procmon"))):
        if isinstance(item, dict):
            event = _event(item, n, "procmon")
            event["time"] = _procmon_time(item, raw)
            event["time_basis"] = "guest_clock_window" if event["time"] else "unavailable"
            events.append(event)
    # Optional other raw sensors may use the same event envelope.
    for n, item in enumerate(_list(raw.get("other_events"))):
        if isinstance(item, dict):
            events.append(_event(item, n, item.get("source", "guest")))

    processes: dict[str, dict] = {}
    pid_history: dict[int, list[dict]] = defaultdict(list)
    for event in events:
        if event["source"] != "sysmon" or event["event_id"] != 1:
            continue
        data = event["details"]
        identity = event["process_guid"] or f"pid:{event['pid']}:{event['time']}:{event['id']}"
        event["process_guid"] = identity
        process = {
            "pid": event["pid"], "ppid": _pid(_field(data, "ParentProcessId")),
            "guid": identity, "parent_guid": _guid(_field(data, "ParentProcessGuid")),
            "image": event["image"], "command_line": str(_field(data, "CommandLine", default="")),
            "children": [], "related": False, "start_time": event["time"],
            "end_time": None, "evidence_ids": [event["id"]],
            "identity_source": "sysmon_guid" if not identity.startswith("pid:") else "pid_time",
        }
        if identity not in processes:
            processes[identity] = process
            if process["pid"] is not None:
                pid_history[process["pid"]].append(process)

    for history in pid_history.values():
        history.sort(key=lambda process: (_time(process["start_time"]) or float('-inf')))

    def resolve_pid(pid: int | None, when: Any) -> dict | None:
        timestamp = _time(when)
        if pid is None or timestamp is None:
            return None
        result = None
        for process in pid_history.get(pid, []):
            start = _time(process["start_time"])
            if start is not None and start <= timestamp:
                # The next creation supersedes this identity even if event 5 is missing.
                result = process
        if result is not None:
            end = _time(result["end_time"])
            if end is not None and timestamp > end:
                return None
        return result

    for event in events:
        if event["source"] == "sysmon" and event["event_id"] == 5:
            process = processes.get(event["process_guid"]) if event["process_guid"] else resolve_pid(event["pid"], event["time"])
            if process:
                process["end_time"] = event["time"]
    for process in processes.values():
        if not process["parent_guid"] and process["ppid"] is not None:
            parent = resolve_pid(process["ppid"], process["start_time"])
            if parent and parent is not process:
                process["parent_guid"] = parent["guid"]
        parent = processes.get(process["parent_guid"])
        if parent and process["guid"] != parent["guid"]:
            parent["children"].append(process["guid"])

    roots: set[str] = set()
    if root_guid and root_guid in processes:
        roots.add(root_guid)
    elif root_pid is not None and launch_time is not None:
        candidates = [p for p in pid_history.get(root_pid, [])
                      if _time(p["start_time"]) is not None
                      and abs(_time(p["start_time"]) - launch_time) <= 15]
        if candidates:
            selected = min(candidates, key=lambda p: abs(_time(p["start_time"]) - launch_time))
            roots.add(selected["guid"])
    elif sample_path and launch_time is not None:
        candidates = [p for p in processes.values() if _path(p["image"]) == sample_path
                      and _time(p["start_time"]) is not None
                      and abs(_time(p["start_time"]) - launch_time) <= 15]
        if len(candidates) == 1:
            roots.add(candidates[0]["guid"])
    if not roots:
        warnings.append("Attribuzione del campione non disponibile: nessuna identità GUID/PID-tempo verificata.")
    related = set(roots)
    pending = list(roots)
    while pending:
        for child in processes[pending.pop()]["children"]:
            if child not in related:
                related.add(child)
                pending.append(child)
    for process in processes.values():
        process["related"] = process["guid"] in related
    for event in events:
        if event["source"] == "sysmon" and event["event_id"] == 6 and not event["process_guid"]:
            # Sysmon driver load has no causal process identity. Header PID/System
            # or a supplied bare PID is not evidence linking it to the sample.
            process = None
        elif event["process_guid"]:
            # An explicit unknown GUID must not fall back to a recycled PID.
            process = processes.get(event["process_guid"])
        else:
            process = resolve_pid(event["pid"], event["time"])
            if process:
                event["process_guid"] = process["guid"]
        event["related"] = bool(process and process["related"])
        event["attribution"] = "process_identity" if process else (
            "time_unavailable" if event["source"] == "procmon" and not event["time"] else "unavailable_global")

    changes = raw.get("changes") or {"registry": [], "files": [], "services": [], "tasks": []}
    if not isinstance(changes, dict):
        changes = {"raw": changes}
    baseline = raw.get("baseline") if isinstance(raw.get("baseline"), dict) else {}
    before = baseline.get("before", {})
    baseline_targets = set()
    if isinstance(before, dict):
        for category in ("files", "registry"):
            for item in _list(before.get(category)):
                if isinstance(item, dict):
                    baseline_targets.add(_path(item.get("path", item.get("key", ""))))
    for target in _list(baseline.get("existing_targets")):
        baseline_targets.add(_path(target))
    for event in events:
        event["noise"] = "background" if not event["related"] else "sample"
        if event["raw"].get("baseline_present") or (event["target"] and _path(event["target"]) in baseline_targets):
            event["baseline_present"] = True
            # Existing resources can still be abused: only presence, not suppression.
        else:
            event["baseline_present"] = False
        if event["baseline_present"] and event["source"] == "procmon" and event["action"] in {
            "ReadFile", "QueryOpen", "QueryInformationFile", "QueryDirectory", "RegQueryValue", "RegQueryKey", "RegEnumKey", "RegEnumValue"
        }:
            event["noise"] = "baseline_read"

    findings: list[dict] = []

    def finding(rule: str, severity: str, title: str, rationale: str, evidence: list[str],
                related_flag: bool, confidence: str = "observed") -> None:
        findings.append({"id": f"finding:{rule}:{len(findings) + 1}", "rule": rule,
                         "severity": severity, "title": title, "rationale": rationale,
                         "evidence_ids": evidence, "related": related_flag, "confidence": confidence})

    for event in events:
        data, number = event["details"], event["event_id"]
        if event["source"] == "defender":
            if number == 1116:
                finding("defender_detection", "high", "Rilevamento Microsoft Defender",
                        "Defender ha registrato un rilevamento; verificare minaccia, percorso e azione nei dati grezzi.",
                        [event["id"]], event["related"])
            elif number == 5001:
                finding("defender_disabled", "high", "Protezione in tempo reale disattivata",
                        "Evento Defender 5001 nella finestra osservata; attribuzione al campione non implicita.",
                        [event["id"]], event["related"])
            continue
        if event["source"] == "procmon":
            if event["action"] in {"RegSetValue", "RegCreateKey"} and _PERSISTENCE.search(event["target"]):
                finding("procmon_persistence", "medium", "Accesso in scrittura a posizione di persistenza",
                        f"Procmon osserva {event['action']} con risultato {data.get('Result', 'sconosciuto')}; un tentativo negato non è una modifica riuscita.",
                        [event["id"]], event["related"], "indicator")
            continue
        if number == 6 and str(_field(data, "Signed", default="")).casefold() == "false":
            finding("unsigned_driver", "high", "Caricamento driver non firmato",
                    "Sysmon 6 riporta Signed=false. Il caricamento è reale; causalità al campione non dimostrata senza identità di processo.",
                    [event["id"]], event["related"])
        elif number == 6 and str(_field(data, "SignatureStatus", default="")).casefold() in {"revoked", "expired", "invalid"}:
            finding("driver_signature", "high", "Firma driver non valida",
                    "Il sensore di caricamento driver riporta una firma revocata/scaduta/non valida; non è da solo una prova BYOVD.",
                    [event["id"]], event["related"])
        elif number == 25:
            finding("process_tamper", "high", "Manomissione processo osservata",
                    "Sysmon 25 segnala process tampering; dettagli e identità rimangono conservati.",
                    [event["id"]], event["related"])
        elif number in {12, 13, 14} and _PERSISTENCE.search(event["target"]) and not str(_field(data, "EventType", default="")).lower().startswith("delete"):
            finding("persistence_registry", "medium", "Modifica registro in posizione di persistenza",
                    "Il percorso modificato abilita avvio automatico/intercettazione/servizi. Può essere lecito; richiede contesto, non è una classificazione malware.",
                    [event["id"]], event["related"], "indicator")
        elif number in {19, 20, 21}:
            finding("wmi_persistence", "medium", "Registrazione WMI permanente",
                    "Sysmon osserva filtro, consumer o binding WMI permanente; possibile persistenza anche da software lecito.",
                    [event["id"]], event["related"], "indicator")
        elif number in {27, 28}:
            finding("sysmon_block", "medium", "Operazione bloccata da Sysmon",
                    "Il sensore riporta un blocco, non l'esecuzione riuscita dell'operazione.",
                    [event["id"]], event["related"])
        if number == 1 and event["related"]:
            command = str(_field(data, "CommandLine", default=""))
            if re.search(r"(?i)(?:^|\s)-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{24,}", command):
                finding("encoded_command", "medium", "PowerShell con comando codificato",
                        "Parametro EncodedCommand osservato nella catena del campione: indicatore contestuale, anche amministrazione lecita.",
                        [event["id"]], True, "indicator")

    for category in ("registry", "files", "services", "tasks"):
        for n, item in enumerate(_list(changes.get(category))):
            if not isinstance(item, dict):
                continue
            item.setdefault("id", f"change:{category}:{n}")
            item.setdefault("related", False)
            item.setdefault("attribution", "snapshot_delta_not_causality")
            if category == "services":
                after = item.get("after") if isinstance(item.get("after"), dict) else {}
                path = str(after.get("PathName", after.get("path", "")))
                service_type = str(after.get("ServiceType", after.get("type", "")))
                if item.get("action") in {"created", "modified", "added"} and (".sys" in path.lower() or "driver" in service_type.lower()):
                    finding("driver_service_delta", "medium", "Servizio driver aggiunto/modificato",
                            "Differenza della baseline servizi con immagine .sys/tipo driver; non prova un caricamento né una vulnerabilità BYOVD.",
                            [item["id"]], bool(item.get("related")), "indicator")

    api_calls, call_chains, syscall_chain = [], [], []
    trace_input = api_events if api_events is not None else _list(raw.get("api_calls", raw.get("api_events")))
    trace_status = []
    chain_by_call: dict[tuple, dict] = {}
    thread_calls: dict[tuple, list[tuple]] = defaultdict(list)
    for n, item in enumerate(trace_input):
        if not isinstance(item, dict):
            continue
        if item.get("type") in {"status", "error", "coverage", "process"}:
            trace_status.append(item)
            continue
        call = dict(item)
        call.setdefault("id", f"api:{n}")
        call.setdefault("time", item.get("timestamp", ""))
        call["pid"] = _pid(item.get("pid"))
        identity = _guid(item.get("process_guid"))
        process = processes.get(identity) if identity else resolve_pid(call["pid"], call["time"])
        call["process_guid"] = process["guid"] if process else identity
        call["related"] = bool(process and process["related"])
        call["coverage"] = "user-mode Frida; non è DTrace né una traccia completa di syscall kernel"
        call["source"] = "frida"
        api_calls.append(call)
        key = (call["pid"], str(item.get("call_id", call["id"])))
        thread_key = (call["pid"], _pid(item.get("tid")))
        tracked_entry = item.get("phase") == "enter" and bool(item.get("call_id")) and thread_key[1] is not None
        if item.get("phase") == "leave":
            entry = chain_by_call.get(key)
            if entry:
                entry.update({"return_event_id": call["id"], "return_time": call["time"],
                              "return_value": item.get("return_value")})
            pending_calls = thread_calls[thread_key]
            if key in pending_calls:
                del pending_calls[pending_calls.index(key):]
            continue
        stack = _list(item.get("stack", item.get("backtrace")))
        chain = {"id": f"chain:{call['id']}", "event_id": call["id"],
                 "pid": call["pid"], "process_guid": call["process_guid"], "time": call["time"],
                 "related": call["related"], "api": item.get("api", item.get("function", "")),
                 "frames": list(reversed(stack)), "direction": "caller_to_callee",
                 "coverage": "stack user-mode osservato all'ingresso; simboli/accuratezza dipendono dal processo",
                 "call_id": item.get("call_id"), "tid": item.get("tid"),
                 "parent_call_id": thread_calls[thread_key][-1][1] if tracked_entry and thread_calls[thread_key] else None}
        call_chains.append(chain)
        chain_by_call[key] = chain
        if tracked_entry:
            thread_calls[thread_key].append(key)
        if str(chain["api"]).split("!")[-1].startswith(("Nt", "Zw")):
            syscall_chain.append(chain)
            chain["kind"] = "nt_user_mode_entry"
            chain["coverage"] = "Entrata Nt*/Zw* user-mode; non dimostra transizione/esecuzione kernel e può essere aggirata da syscall dirette"

    sensors = raw.get("sensors", raw.get("capabilities", {})) or {}
    sensors = dict(sensors) if isinstance(sensors, dict) else {"raw_status": sensors}
    procmon_markers = [e for e in events if e["source"] == "procmon" and e["category"] == "sensor"
                      and e["action"] in {"error", "truncated"}]
    procmon_unknown_times = sum(e["source"] == "procmon" and e["category"] != "sensor" and not e["time"] for e in events)
    if procmon_markers:
        warnings.append("Parser Procmon parziale/non disponibile: limiti o errore CSV; marker conservati negli eventi.")
    if procmon_unknown_times:
        warnings.append("Timestamp Procmon non risolti: nessuna attribuzione basata solo sul PID.")
    for phase in ("before", "after"):
        coverage = baseline.get(phase)
        if isinstance(coverage, dict) and any(isinstance(c, dict) and c.get("status") in {"partial", "error", "unavailable"}
                                              for c in coverage.values()):
            warnings.append(f"Baseline {phase} incompleta: risorse non osservate non provano creazione/eliminazione.")
    status = defender_raw.get("status", "unavailable" if not defender_events else "completed")
    detections = _list(defender_raw.get("detections"))
    detection_events = [event for event in defender_events if event["event_id"] == 1116]
    for n, detection in enumerate(detections):
        if isinstance(detection, dict) and not detection_events:
            finding("defender_detection_record", "high", "Rilevamento Defender registrato",
                    "Record Get-MpThreatDetection nella finestra osservata; non è un verdetto derivato dall'assenza di eventi.",
                    [str(detection.get("id", f"defender-detection:{n}"))], False)
    defender = dict(defender_raw)
    defender.update({"status": status, "events": defender_events,
                     "detections": detections,
                     "assessment": "detections_observed" if detections or detection_events else "no_hit_not_clean",
                     "detail": "Nessun rilevamento non significa pulito; disponibilità e finestre dei sensori limitano la copertura."})
    if status not in {"completed", "available"}:
        warnings.append("Copertura Defender non completa/disponibile; nessuna conclusione di pulizia.")
    if not api_calls:
        warnings.append("Traccia API user-mode assente: sensore non disponibile/non richiesto o nessun hook osservato.")
    categories = Counter(event["category"] for event in events)
    counts = {"events": len(events), "related_events": sum(event["related"] for event in events),
              "processes": len(processes), "related_processes": len(related),
              "api_calls": len(api_calls), "findings": len(findings), "by_category": dict(categories)}
    return {
        "processes": list(processes.values()), "events": events,
        "registry": [e for e in events if e["category"] == "registry"],
        "files": [e for e in events if e["category"] == "file"],
        "network": [e for e in events if e["category"] == "network"],
        "drivers": [e for e in events if e["category"] == "driver"],
        "api_calls": api_calls, "call_chains": call_chains, "syscall_chain": syscall_chain,
        "api_sensor_events": trace_status, "defender": defender, "changes": changes,
        "counts": counts,
        "noise": {"retained_raw_events": len(events), "removed_events": 0,
                  "background_events": len(events) - counts["related_events"],
                  "baseline_present_events": sum(e["baseline_present"] for e in events),
                  "baseline_read_events": sum(e["noise"] == "baseline_read" for e in events),
                  "default_filter": "related", "policy": "Solo etichette: driver, sicurezza e differenze globali sempre conservati."},
        "capabilities": sensors, "warnings": list(dict.fromkeys(str(w) for w in warnings)),
        "findings": findings, "baseline": raw.get("baseline", {}), "launch": launch,
        "coverage": {"sysmon_event_count": len(source_events), "event_cap": raw.get("event_cap", 50000),
                     "truncated": bool(raw.get("truncated", False) or procmon_markers),
                     "procmon": {"events": sum(e["source"] == "procmon" for e in events),
                                 "unresolved_timestamps": procmon_unknown_times,
                                 "parser_status": "partial" if procmon_markers else ("available" if raw.get("procmon") else "unavailable")},
                     "api": "user_mode_only"},
    }


def attach_kernel(dynamic: dict, report: dict, requested=True) -> dict:
    """Keep genuine kernel ETW distinct from user-mode Nt hooks and retain all rows."""
    from lab.kernel import normalize_kernel

    kernel = normalize_kernel(report, processes=dynamic.get("processes", []))
    dynamic["kernel"] = kernel
    processes = {item.get("guid"): item for item in dynamic.get("processes", [])}
    for record in kernel.get("events", []):
        kind = str(record.get("kind", "unknown"))
        process = processes.get(record.get("process_guid"), {})
        category = "syscall" if kind.startswith("syscall") else "kernel"
        dynamic["events"].append({
            **record, "source": "microsoft_kernel_etw", "category": category,
            "action": kind, "event_id": record.get("raw", {}).get("opcode"),
            "image": process.get("image", ""),
            "target": record.get("syscall_address") or record.get("ntstatus") or "",
            "related": record.get("related") is True, "baseline_present": False,
            "noise": "sample" if record.get("related") else "background",
            "attribution": record.get("identity_status", "unavailable_global"),
            "coverage": "kernel ETW osservato; perdita, ring buffer e decodifica limitano la copertura",
        })
    counts = dynamic["counts"]
    counts["events"] = len(dynamic["events"])
    counts["related_events"] = sum(item.get("related") is True for item in dynamic["events"])
    counts["by_category"] = dict(Counter(item["category"] for item in dynamic["events"]))
    counts["kernel_events"] = kernel.get("counts", {}).get("events", 0)
    counts["kernel_syscalls"] = kernel.get("counts", {}).get("syscall_enter", 0)
    counts["kernel_stacks"] = kernel.get("counts", {}).get("stackwalk", 0)
    dynamic["noise"].update(retained_raw_events=counts["events"],
                            background_events=counts["events"] - counts["related_events"])
    dynamic["coverage"]["kernel"] = kernel.get("coverage", {})
    dynamic["capabilities"]["kernel"] = {
        "status": kernel.get("status", "unavailable"),
        "detail": f"ETW kernel: {counts['kernel_syscalls']} ingressi syscall, {counts['kernel_stacks']} stackwalk osservati. Non è una garanzia di copertura totale.",
        "requested": bool(requested),
    }
    if requested:
        dynamic["warnings"] = list(dict.fromkeys(dynamic["warnings"] + kernel.get("warnings", [])))
        if kernel.get("status") == "unavailable":
            dynamic["warnings"].append("Tracing kernel non disponibile/osservato; nessuna copertura viene presunta.")
    return dynamic

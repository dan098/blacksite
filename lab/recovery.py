"""Recover independently exported evidence, never infer missing Defender verdicts."""
import json
from pathlib import Path


def _object(path, maximum=4 * 1024 * 1024):
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
            return {}
        value = json.loads(path.read_text(encoding="utf-8-sig"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def recover(directory: Path) -> dict:
    directory = Path(directory)
    source = directory / "sysmon.jsonl"
    if source.is_symlink() or not source.is_file() or source.stat().st_size > 64 * 1024 * 1024:
        return {}
    events = []
    gaps = []
    with source.open(encoding="utf-8-sig") as stream:
        for line in stream:
            if len(events) >= 50000:
                gaps.append("Cap di recupero Sysmon raggiunto")
                break
            if len(line) > 256 * 1024:
                gaps.append("Record Sysmon oltre limite: omesso")
                continue
            try:
                value = json.loads(line)
                if isinstance(value, dict):
                    events.append(value)
            except ValueError:
                gaps.append("Record Sysmon non decodificabile: omesso")
    if not events:
        return {}
    state = _object(directory / "collector-state.json")
    sensors = _object(directory / "sensors.json")
    launch = _object(directory / "launch.json")
    stage = _object(directory / "collector-stage.json")
    defender = _object(directory / "defender-state.json", 32 * 1024 * 1024)
    if not defender:
        defender = {"status": "partial", "detail": "EVTX può essere disponibile, ma il JSON Defender non è stato raccolto: verdetto non valutabile", "events": [], "detections": []}
        sensors["defender"] = {"status": "partial", "detail": defender["detail"]}
    sensors["combined_export"] = {"status": "partial", "detail": "telemetry.json assente; recuperate fonti standalone effettive"}
    return {
        "schema_version": 1, "recovered": True,
        "sample_path": launch.get("sample_path", state.get("sample_path")),
        "root_pid": launch.get("root_pid"), "launch_time": launch.get("launch_time"),
        "launch": launch, "start_time": state.get("start_time"), "end_time": stage.get("time"),
        "procmon_clock": state.get("procmon_clock", {}), "sysmon": events,
        "defender": defender, "sensors": sensors, "changes": {}, "event_cap": 50000,
        "truncated": bool(gaps),
        "baseline": {"before": sensors.get("baseline_before", state.get("baseline_coverage", {})), "after": sensors.get("baseline_after", {})},
        "warnings": ["Export combinato non disponibile: report parziale ricostruito dalle fonti standalone, senza inventare sensori/verdetti."] + list(dict.fromkeys(gaps)),
    }

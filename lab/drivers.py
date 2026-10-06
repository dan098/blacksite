import json
import re
from pathlib import Path


def enrich(dynamic: dict, tools: Path):
    cache = tools / "loldrivers.json"
    if not cache.is_file() or cache.stat().st_size > 20 * 1024 * 1024:
        dynamic["byovd"] = {"status": "unavailable", "matches": [], "detail": "Cache hash LOLDrivers non disponibile; nessuna prova di sfruttamento."}
        return dynamic
    try:
        payload = json.loads(cache.read_text())
        index = {}
        for record in payload.get("records", [])[:10000]:
            for algorithm, digest in record.get("hashes", {}).items():
                if digest:
                    index[(algorithm.lower(), digest.lower())] = record
        matches = []
        for event in dynamic.get("drivers", []):
            details = event.get("details", {})
            hash_string = str(details.get("Hashes", details.get("hashes", "")))
            records = {}
            for algorithm, digest in re.findall(r"(SHA256|SHA1|MD5)=([0-9a-fA-F]{32,64})", hash_string, re.IGNORECASE):
                record = index.get((algorithm.lower(), digest.lower()))
                if record:
                    records[record["id"]] = record
            if records:
                event["loldrivers_matches"] = list(records.values())
                for record in records.values():
                    matches.append({"event_id": event["id"], "driver": event.get("target", event.get("image")), "record_id": record["id"], "category": record.get("category"), "related": event.get("related", False), "evidence": "observed_driver_load_exact_hash", "source": payload.get("source")})
                    dynamic.setdefault("findings", []).append({"id": "loldrivers:" + event["id"] + ":" + record["id"], "severity": "high", "title": "Driver caricato presente in LOLDrivers", "description": "Hash esatto associato a un evento Sysmon DriverLoad. Driver noto non dimostra uno sfruttamento BYOVD; correlare servizi e accessi al device.", "related": event.get("related", False), "evidence_ids": [event["id"]], "confidence": "exact_hash"})
        dynamic["byovd"] = {"status": "completed", "matches": matches, "cache_retrieved_at": payload.get("retrieved_at"), "detail": "DriverLoad + hash noti + servizi/DeviceIoControl quando osservabili. Nessuno sfruttamento o caricamento driver automatico; no-hit non esclude BYOVD."}
    except (OSError, ValueError, TypeError, KeyError) as exc:
        dynamic["byovd"] = {"status": "error", "matches": [], "detail": str(exc)[:200]}
    return dynamic

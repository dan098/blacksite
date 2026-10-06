"""Add indexed event pages while keeping the original reports and a SQLite rollback."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time

from .config import SETTINGS
from .defender_update import _require_service_stopped
from .store import Store
from .worker import public_job


def main():
    os.umask(0o077)
    _require_service_stopped()
    store = Store(SETTINGS.db_path)
    with store.connect() as conn:
        ids = [row[0] for row in conn.execute("SELECT id FROM jobs ORDER BY created")]
    pending = []
    for job_id in ids:
        job = store.get(job_id)
        if any(isinstance(run.get("dynamic"), dict) and not run.get("_events_indexed") for run in job.get("runs", [])):
            pending.append(job_id)
    if not pending:
        print(json.dumps({"status": "already_migrated", "jobs": 0}))
        return 0
    backups = SETTINGS.data / "backups"
    backups.mkdir(mode=0o700, parents=True, exist_ok=True)
    backup = backups / f"lab-before-event-index-{int(time.time())}.sqlite3"
    with store.connect() as source, sqlite3.connect(backup) as destination:
        source.backup(destination)
    backup.chmod(0o600)
    proof = {"status": "migrated", "backup": str(backup), "jobs": []}
    for job_id in pending:
        job = store.get(job_id)
        original_bytes = len(Store.encode(job))
        raw_path = SETTINGS.jobs / job_id / "report.json"
        if not raw_path.exists():
            raw_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with raw_path.open("w", encoding="utf-8") as stream:
                json.dump(public_job(job), stream, ensure_ascii=False, separators=(",", ":"))
            artifact_id = hashlib.sha256(b"report.json").hexdigest()[:20]
            job.setdefault("artifacts", []).append({"id": artifact_id, "name": "report.json", "size": raw_path.stat().st_size,
                "kind": "report", "run": None, "_path": str(raw_path), "url": f"/api/jobs/{job_id}/artifacts/{artifact_id}"})
        counts = {}
        for run in job.get("runs", []):
            dynamic = run.get("dynamic")
            if not isinstance(dynamic, dict) or run.get("_events_indexed"):
                continue
            rows = dynamic.get("events", [])
            store.replace_events(job_id, run["profile"], rows)
            actual = store.events_page(job_id, run["profile"], related=False, limit=1)
            if actual["total"] != len(rows):
                raise RuntimeError("Event index count mismatch: no cache compaction")
            counts[run["profile"]] = len(rows)
            run["_events_indexed"] = True
        store.update(job_id, runs=job.get("runs", []), artifacts=job.get("artifacts", []))
        cached = store.get(job_id)
        proof["jobs"].append({"id": job_id, "events": counts, "old_payload_bytes": original_bytes,
                              "compact_payload_bytes": len(Store.encode(cached)), "raw_report_bytes": raw_path.stat().st_size})
    (SETTINGS.data / "event-migration-proof.json").write_text(json.dumps(proof, indent=2))
    print(json.dumps(proof, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

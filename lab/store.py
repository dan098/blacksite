import hashlib
import json
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

TERMINAL = {"completed", "partial", "failed", "cancelled"}

def utcnow():
    return datetime.now(timezone.utc).isoformat()

class Store:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.RLock()
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, created TEXT NOT NULL, status TEXT NOT NULL, payload TEXT NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS shares (digest TEXT PRIMARY KEY, job TEXT NOT NULL, expires REAL NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS event_runs (job TEXT NOT NULL, profile TEXT NOT NULL, total INTEGER NOT NULL, PRIMARY KEY(job,profile))")
            conn.execute("CREATE TABLE IF NOT EXISTS event_rows (job TEXT NOT NULL, profile TEXT NOT NULL, position INTEGER NOT NULL, related INTEGER NOT NULL, category TEXT NOT NULL, searchable TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(job,profile,position))")
            conn.execute("CREATE INDEX IF NOT EXISTS events_filter ON event_rows(job,profile,related,category,position)")

    def connect(self):
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def encode(job):
        from lab.views import compact_job
        return json.dumps(compact_job(job, indexed_only=True), ensure_ascii=False, separators=(",", ":"))

    def put(self, job):
        with self.lock, self.connect() as conn:
            conn.execute("INSERT INTO jobs VALUES(?,?,?,?)", (job["id"], job["created_at"], job["status"], self.encode(job)))

    def get(self, job_id):
        with self.connect() as conn:
            row = conn.execute("SELECT payload FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            return None
        return json.loads(row["payload"])

    def update(self, job_id, **changes):
        with self.lock, self.connect() as conn:
            row = conn.execute("SELECT payload FROM jobs WHERE id=?", (job_id,)).fetchone()
            if not row:
                raise KeyError(job_id)
            job = json.loads(row["payload"])
            job.update(changes)
            job["updated_at"] = utcnow()
            conn.execute("UPDATE jobs SET status=?,payload=? WHERE id=?", (job["status"], self.encode(job), job_id))
            return job

    def list(self, limit=100, offset=0):
        with self.connect() as conn:
            rows = conn.execute("SELECT payload FROM jobs ORDER BY created DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def pending_count(self):
        with self.connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM jobs WHERE status NOT IN ('completed','partial','failed','cancelled')").fetchone()[0]
    def cancel_requested(self, job_id):
        with self.connect() as conn:
            row = conn.execute("SELECT json_extract(payload,'$.cancel_requested') FROM jobs WHERE id=?", (job_id,)).fetchone()
        return row is None or bool(row[0])

    def replace_events(self, job_id, profile, events):
        """Checkpoint complete normalized events once; an empty index is still authoritative."""
        def records():
            for position, event in enumerate(events):
                payload = json.dumps(event, ensure_ascii=False)
                yield (job_id, profile, position, int(bool(event.get("related"))),
                       str(event.get("category", "")), payload.casefold(), payload)
        with self.lock, self.connect() as conn:
            if not conn.execute("SELECT 1 FROM jobs WHERE id=?", (job_id,)).fetchone():
                raise KeyError(job_id)
            conn.execute("DELETE FROM event_rows WHERE job=? AND profile=?", (job_id, profile))
            conn.executemany("INSERT INTO event_rows VALUES(?,?,?,?,?,?,?)", records())
            conn.execute("INSERT INTO event_runs VALUES(?,?,?) ON CONFLICT(job,profile) DO UPDATE SET total=excluded.total", (job_id, profile, len(events)))

    def events_page(self, job_id, profile, related=True, category="", q="", offset=0, limit=200):
        offset, limit = max(0, offset), max(1, min(500, limit))
        with self.connect() as conn:
            if not conn.execute("SELECT 1 FROM event_runs WHERE job=? AND profile=?", (job_id, profile)).fetchone():
                return None  # Older unindexed jobs retain the original full-payload reader.
            where, args = ["job=?", "profile=?"], [job_id, profile]
            if related:
                where.append("related=1")
            if category:
                where.append("category=?")
                args.append(category)
            if q:
                where.append("instr(searchable,?)>0")
                args.append(q[:200].casefold())
            condition = " AND ".join(where)
            total = conn.execute("SELECT COUNT(*) FROM event_rows WHERE " + condition, args).fetchone()[0]
            rows = conn.execute("SELECT payload FROM event_rows WHERE " + condition + " ORDER BY position LIMIT ? OFFSET ?", (*args, limit, offset)).fetchall()
        return {"items": [json.loads(row["payload"]) for row in rows], "total": total, "offset": offset, "limit": limit}


    def interrupted(self):
        with self.connect() as conn:
            ids = [row[0] for row in conn.execute("SELECT id FROM jobs WHERE status NOT IN ('completed','partial','failed','cancelled')")]
        for job_id in ids:
            job = self.get(job_id)
            warnings = job.get("warnings", []) + ["Esecuzione interrotta dal riavvio del servizio; nessuna ripresa su VM non pulita."]
            self.update(job_id, status="failed", warnings=warnings, finished_at=utcnow())

    def share(self, job_id, hours):
        token = secrets.token_urlsafe(32)
        expires = time.time() + hours * 3600
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self.connect() as conn:
            conn.execute("DELETE FROM shares WHERE job=? OR expires<?", (job_id, time.time()))
            conn.execute("INSERT INTO shares VALUES(?,?,?)", (digest, job_id, expires))
        return token, datetime.fromtimestamp(expires, timezone.utc).isoformat()

    def shared_job(self, token):
        if len(token) > 128:
            return None
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self.connect() as conn:
            row = conn.execute("SELECT job FROM shares WHERE digest=? AND expires>?", (digest, time.time())).fetchone()
        return self.get(row["job"]) if row else None

    def revoke(self, job_id):
        with self.connect() as conn:
            conn.execute("DELETE FROM shares WHERE job=?", (job_id,))

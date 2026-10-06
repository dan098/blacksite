import json
import pytest

from lab.store import Store, utcnow
from lab.views import DISPLAY_CAP


def test_compact_cache_retains_private_paths_and_complete_index(tmp_path):
    store = Store(tmp_path / "lab.sqlite3")
    job = {"id": "a" * 32, "created_at": utcnow(), "status": "running", "_sample_path": "private"}
    store.put(job)
    rows = [{"id": str(n), "related": n % 2 == 0, "category": "registry", "target": "Straße"} for n in range(1000)]
    store.replace_events(job["id"], "standard", rows)
    store.update(job["id"], runs=[{"profile": "standard", "_events_indexed": True, "dynamic": {"events": rows, "counts": {"events": 1000}}}])
    cached = store.get(job["id"])
    assert cached["_sample_path"] == "private"
    assert len(cached["runs"][0]["dynamic"]["events"]) == DISPLAY_CAP
    page = store.events_page(job["id"], "standard", related=False, q="STRASSE", offset=700, limit=10)
    assert page["total"] == 1000
    assert [x["id"] for x in page["items"]] == [str(n) for n in range(700, 710)]
    assert store.events_page(job["id"], "standard", related=True)["total"] == 500
    assert store.events_page(job["id"], "standard", q="' OR 1=1 --")["total"] == 0
    assert len(rows) == 1000
    assert not store.cancel_requested(job["id"])
    store.update(job["id"], cancel_requested=True)
    assert store.cancel_requested(job["id"])


def test_legacy_data_not_compacted_until_indexed(tmp_path):
    store = Store(tmp_path / "lab.sqlite3")
    rows = [{"id": str(n)} for n in range(400)]
    store.put({"id": "b" * 32, "created_at": utcnow(), "status": "completed", "runs": [{"profile": "standard", "dynamic": {"events": rows}}]})
    assert len(store.get("b" * 32)["runs"][0]["dynamic"]["events"]) == 400
    assert store.events_page("b" * 32, "standard") is None


def test_event_replacement_is_atomic_and_empty_index_authoritative(tmp_path):
    store = Store(tmp_path / "lab.sqlite3")
    job_id = "c" * 32
    store.put({"id": job_id, "created_at": utcnow(), "status": "running"})
    rows = [{"id": "one", "related": True}]
    store.replace_events(job_id, "standard", rows)
    with pytest.raises(AttributeError):
        store.replace_events(job_id, "standard", [None])
    assert store.events_page(job_id, "standard")["items"] == rows
    store.replace_events(job_id, "standard", [])
    assert store.events_page(job_id, "standard")["total"] == 0
    assert store.events_page(job_id, "standard")["items"] == []

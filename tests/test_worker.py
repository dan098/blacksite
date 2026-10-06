import json
from pathlib import Path
import pytest
from lab.config import ROOT, Settings
from lab.store import Store, utcnow
from lab.worker import Worker


@pytest.mark.parametrize("kernel", [False, True])
def test_export_failure_always_destroys_private_vm_state(tmp_path, monkeypatch, kernel):
    import lab.vm
    import lab.worker
    settings = Settings(root=ROOT, data=tmp_path, token="x" * 40)
    settings.prepare()
    store = Store(settings.db_path)
    job_id = "b" * 32
    store.put({"id": job_id, "status": "running", "created_at": utcnow(), "sha256": "a" * 64, "warnings": []})
    worker = Worker(settings, store)
    cleaned = []
    class FakeVM:
        def __init__(self, run_dir, base_dir, profile):
            self.run_dir = run_dir
        def start(self):
            (self.run_dir / "network.pcap").write_bytes(b"probe")
        def wait_agent(self, timeout):
            return True
        def wait_desktop(self, timeout):
            return True
        def exec(self, ps, timeout):
            return 0, "", ""
        def push(self, src, dst):
            pass
        def screenshot(self, path):
            path.write_bytes(b"probe")
        def pull(self, src, dst, max_bytes):
            raise OSError("not present")
        def stop(self):
            pass
        def cleanup(self):
            cleaned.append(True)
    monkeypatch.setattr(lab.vm, "AnalysisVM", FakeVM)
    def failed_copy(src, dst):
        raise OSError("ENOSPC")
    monkeypatch.setattr(lab.worker.shutil, "copy2", failed_copy)
    sample = tmp_path / "probe.ps1"
    sample.write_text("Write-Output benign")
    runs = [{"profile": "standard", "status": "pending"}]
    with pytest.raises(OSError, match="ENOSPC"):
        worker.dynamic(job_id, sample, {"id": "standard", "trace": False, "interaction": False, "kernel": kernel}, 0, runs, 0)
    assert cleaned == [True]
    assert worker.active_vm is None
    assert any("Artefatto kernel non acquisito (kernel.etl)" in warning for warning in runs[0].get("warnings", [])) is kernel


def test_terminal_state_is_published_only_after_full_report(tmp_path, monkeypatch):
    import lab.static_analysis
    import lab.hybrid
    import lab.worker
    settings = Settings(root=ROOT, data=tmp_path, token="x" * 40)
    settings.prepare()
    store = Store(settings.db_path)
    job_id = "d" * 32
    sample = tmp_path / "benign.txt"
    sample.write_text("benign")
    store.put({"id": job_id, "status": "queued", "created_at": utcnow(), "name": "benign.txt",
               "sha256": "a" * 64, "_sample_path": str(sample), "warnings": [], "runs": [],
               "options": {"duration": 15}})
    monkeypatch.setattr(lab.static_analysis, "analyze", lambda *a: {"av": {"status": "completed"}, "hashes": {"sha256": "a" * 64}})
    monkeypatch.setattr(lab.hybrid, "lookup", lambda *a: {"status": "disabled"})
    original = lab.worker.public_job
    observed = []
    def while_reporting(job):
        observed.append(store.get(job_id)["status"])
        return original(job)
    monkeypatch.setattr(lab.worker, "public_job", while_reporting)
    Worker(settings, store).execute(job_id)
    finished = store.get(job_id)
    assert observed == ["reporting"]
    assert finished["status"] == "completed"
    artifact = next(x for x in finished["artifacts"] if x["name"] == "report.json")
    report = json.loads(Path(artifact["_path"]).read_text())
    assert report["status"] == "completed"
    assert "_sample_path" not in report


def test_early_run_failure_preserves_host_evidence_and_never_claims_completed(tmp_path, monkeypatch):
    import lab.static_analysis
    import lab.hybrid
    settings = Settings(root=ROOT, data=tmp_path, token="x" * 40)
    settings.prepare()
    store = Store(settings.db_path)
    job_id = "e" * 32
    sample = tmp_path / "benign.ps1"
    sample.write_text("Write-Output benign")
    store.put({"id": job_id, "status": "queued", "created_at": utcnow(), "name": "benign.ps1",
               "sha256": "a" * 64, "_sample_path": str(sample), "warnings": [],
               "runs": [{"profile": "standard", "status": "pending"}], "options": {"duration": 15}})
    monkeypatch.setattr(lab.static_analysis, "analyze", lambda *a: {"hashes": {"sha256": "a" * 64}})
    monkeypatch.setattr(lab.hybrid, "lookup", lambda *a: {"status": "disabled"})
    worker = Worker(settings, store)
    def fail_after_isolation(*args):
        output = settings.jobs / job_id / "standard"
        output.mkdir()
        (output / "namespace.json").write_text(json.dumps({"confirmed": True}))
        (output / "network.pcap").write_bytes(b"captured-before-failure")
        raise TimeoutError("prepare sync timed out; no sample launched")
    monkeypatch.setattr(worker, "dynamic", fail_after_isolation)
    worker.execute(job_id)
    job = store.get(job_id)
    run = job["runs"][0]
    assert job["status"] == "partial" and run["status"] == "failed"
    assert run["dynamic"]["isolation"]["confirmed"] is True
    assert {artifact["name"] for artifact in run["artifacts"]} == {"namespace.json", "network.pcap"}
    assert "conclusione" in run["dynamic"]["warnings"][0]

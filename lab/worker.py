import hashlib
import json
import logging
import queue
import shutil
import threading
import time
from pathlib import Path

from lab.config import PROFILE_MAP
from lab.store import utcnow
from lab.integrations import elastic_lookup
from lab.network import summarize

LOG = logging.getLogger("sandbox.worker")
DYNAMIC_EXTENSIONS = {".exe", ".ps1", ".bat", ".cmd", ".py"}
GUEST_ARTIFACTS = {
    "telemetry.json": "telemetry", "launch.json": "telemetry", "api.jsonl": "api", "sysmon.jsonl": "telemetry",
    "sysmon.evtx": "events", "defender.evtx": "events", "procmon.pml": "procmon", "procmon.csv": "procmon",
    "baseline-before.json": "baseline", "baseline-after.json": "baseline", "collector-state.json": "telemetry", "sensors.json": "telemetry",
    "sysmon.xml": "events", "defender.xml": "events", "trace-status.json": "api", "trace-supervisor.json": "api",
    "launch-task.json": "telemetry", "powershell.evtx": "events", "tasks.evtx": "events", "codeintegrity.evtx": "events",
    "collector-stage.json": "telemetry", "collector-error-finish.json": "telemetry",
    "defender-state.json": "telemetry",
    "kernel.etl": "kernel", "kernel_events.jsonl": "kernel",
    "kernel_start.json": "kernel", "kernel_status.json": "kernel",
    "kernel_stop.json": "kernel", "kernel_decode.json": "kernel",
    "kernel_commands.jsonl": "kernel", "payloads.json": "payload_manifest",
}


def read_json(path, default=None, max_bytes=32 * 1024 * 1024):
    if not path.exists() or path.stat().st_size > max_bytes:
        return default
    return json.loads(path.read_text(encoding="utf-8-sig"))


class Cancelled(Exception):
    pass


class Worker:
    def __init__(self, settings, store):
        self.settings = settings
        self.store = store
        self.queue = queue.Queue(maxsize=settings.max_queue)
        self.stopping = threading.Event()
        self.active_vm = None
        self.thread = threading.Thread(target=self.loop, name="sandbox-worker", daemon=True)

    def start(self):
        self.store.interrupted()
        self.thread.start()

    def submit(self, job_id):
        self.queue.put_nowait(job_id)

    def close(self):
        self.stopping.set()
        if self.active_vm:
            try:
                self.active_vm.stop()
            except Exception:
                LOG.exception("VM stop during shutdown")
        if self.thread.is_alive():
            self.thread.join(timeout=20)

    def check_cancel(self, job_id):
        if self.stopping.is_set() or self.store.cancel_requested(job_id):
            raise Cancelled()

    def loop(self):
        while not self.stopping.is_set():
            try:
                job_id = self.queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self.execute(job_id)
            except Cancelled:
                self.store.update(job_id, status="cancelled", finished_at=utcnow())
            except Exception as exc:
                LOG.exception("Job %s failed", job_id)
                job = self.store.get(job_id)
                self.store.update(job_id, status="failed", finished_at=utcnow(), warnings=job.get("warnings", []) + [str(exc)[:500]])
            finally:
                self.queue.task_done()

    def artifact(self, job_id, path, kind, run=None, verified_payloads=None):
        if not path.is_file() or path.is_symlink():
            return None
        if path.name.startswith("payload-") and path.suffix == ".bin" and path.name not in (verified_payloads or ()):
            return None
        artifact_id = hashlib.sha256((str(path.relative_to(self.settings.jobs / job_id))).encode()).hexdigest()[:20]
        return {"id": artifact_id, "name": path.name, "size": path.stat().st_size, "kind": kind, "run": run,
                "_path": str(path.resolve()), "url": f"/api/jobs/{job_id}/artifacts/{artifact_id}"}

    def execute(self, job_id):
        from lab.static_analysis import analyze
        job = self.store.get(job_id)
        self.check_cancel(job_id)
        output = self.settings.jobs / job_id
        static_dir = output / "static"
        static_dir.mkdir(parents=True, exist_ok=True)
        sample = Path(job["_sample_path"])
        self.store.update(job_id, status="static")
        static = analyze(sample, static_dir, self.settings.tools)
        from lab.hybrid import lookup
        static["hybrid_analysis"] = lookup(job["sha256"])
        (static_dir / "static.json").write_text(json.dumps(static, ensure_ascii=False, indent=2), encoding="utf-8")
        self.check_cancel(job_id)
        artifacts = [artifact for path in sorted(static_dir.iterdir()) if (artifact := self.artifact(job_id, path, "static"))]
        self.store.update(job_id, static=static, artifacts=artifacts)
        runs = job.get("runs", [])
        failures = sum(isinstance(value, dict) and value.get("status") in {"error", "timeout"} for key, value in static.items() if key not in {"capabilities", "reputation", "hybrid_analysis"})
        skipped = 0
        for index, run in enumerate(runs):
            self.check_cancel(job_id)
            if sample.suffix.lower() not in DYNAMIC_EXTENSIONS:
                run.update(status="skipped", warnings=["Formato non eseguibile supportato: solo analisi statica; i driver .sys non vengono installati automaticamente."])
                skipped += 1
            else:
                try:
                    run, added = self.dynamic(job_id, sample, PROFILE_MAP[run["profile"]], job["options"]["duration"], runs, index)
                    artifacts.extend(added)
                    if run["status"] in {"failed", "partial"}:
                        failures += 1
                except Cancelled:
                    raise
                except Exception as exc:
                    LOG.exception("Run %s failed", run["profile"])
                    run.update(status="failed", warnings=run.get("warnings", []) + [str(exc)[:500]])
                    # Early guest-agent failures still leave useful host-side isolation/PCAP evidence.
                    failed_dir = output / run["profile"]
                    if failed_dir.is_dir():
                        preserved = [item for path in sorted(failed_dir.iterdir()) if (item := self.artifact(job_id, path, "runtime", run["profile"]))]
                        run["artifacts"] = preserved
                        artifacts.extend(preserved)
                        run["dynamic"] = {"isolation": read_json(failed_dir / "namespace.json", {}),
                                          "warnings": ["Esecuzione interrotta; nessuna conclusione comportamentale. Consultare gli artefatti preservati."]}
                    failures += 1
            runs[index] = run
            self.store.update(job_id, runs=runs, artifacts=artifacts)
        self.check_cancel(job_id)
        warnings = self.store.get(job_id).get("warnings", [])
        if skipped:
            warnings += ["Una o più esecuzioni dinamiche saltate per formato non supportato."]
        summary = self.make_summary(static, runs)
        final = "partial" if failures or skipped else "completed"
        # Terminal status means the full raw report is already downloadable.
        result = self.store.update(job_id, status="reporting", runs=runs, artifacts=artifacts, warnings=warnings, summary=summary)
        result.update(status=final, finished_at=utcnow())
        result_path = output / "report.json"
        with result_path.open("w", encoding="utf-8") as stream:
            json.dump(public_job(result), stream, ensure_ascii=False, separators=(",", ":"))
        if artifact := self.artifact(job_id, result_path, "report"):
            artifacts.append(artifact)
        self.store.update(job_id, status=final, artifacts=artifacts, finished_at=result["finished_at"])

    def dynamic(self, job_id, sample, profile, duration, runs, index):
        from lab.vm import AnalysisVM
        from lab.telemetry import normalize
        run = runs[index]
        run.update(status="booting", started_at=utcnow())
        self.store.update(job_id, status="running", runs=runs)
        out = self.settings.jobs / job_id / profile["id"]
        out.mkdir(parents=True, exist_ok=True)
        runtime = self.settings.data / "runtime" / (job_id[:12] + "-" + profile["id"])
        collected = runtime / "collected"
        collected.mkdir(parents=True, exist_ok=True, mode=0o700)
        vm = AnalysisVM(runtime, self.settings.base_dir, profile)
        self.active_vm = vm
        added = []
        guest_dir = "C:\\Sandbox\\runs\\" + job_id[:12] + "-" + profile["id"]
        guest_sample = guest_dir + "\\sample" + sample.suffix.lower()
        base_command = f"& 'C:\\Sandbox\\tools\\collect.ps1' -OutputDir '{guest_dir}' -SamplePath '{guest_sample}' -Duration {int(duration)}"
        if profile.get("trace"):
            base_command += " -Trace"
        if profile.get("kernel"):
            base_command += " -Kernel"
        launched = False
        cancelled = False
        try:
            vm.start()
            if not vm.wait_agent(timeout=360):
                raise RuntimeError("Guest agent non pronto entro il limite")
            if not vm.wait_desktop(timeout=180):
                raise RuntimeError("Desktop interattivo Quickemu non pronto; campione non trasferito")
            self.check_cancel(job_id)
            # Versioned trusted collectors can be updated without ever modifying the clean base.
            for script in sorted((self.settings.root / "guest").iterdir()):
                if script.is_file() and not script.is_symlink() and script.suffix.lower() in {".ps1", ".py", ".js", ".xml", ".cs", ".wprp"}:
                    if script.stat().st_size > 2 * 1024 * 1024:
                        raise RuntimeError("Collector fidato oltre limite")
                    vm.push(script, "C:\\Sandbox\\tools\\" + script.name)
            rc, stdout, stderr = vm.exec(f"New-Item -ItemType Directory -Force '{guest_dir}' | Out-Null", timeout=30)
            if rc:
                raise RuntimeError("Preparazione directory guest fallita: " + stderr[:300])
            rc, stdout, stderr = vm.exec(base_command + " -Mode prepare", timeout=350)
            if rc:
                raise RuntimeError("Avvio sensori fallito: " + (stdout or stderr)[-2048:])
            self.check_cancel(job_id)
            # File reaches the guest only after all fail-closed isolation checks and baseline.
            vm.push(sample, guest_sample)
            vm.screenshot(collected / "desktop-before.png")
            rc, stdout, stderr = vm.exec(base_command + " -Mode launch", timeout=60)
            launched = True
            if rc:
                run.setdefault("warnings", []).append("Avvio sample ha restituito un errore: " + (stderr or stdout)[-300:])
            run.update(status="collecting")
            self.store.update(job_id, runs=runs)
            end = time.monotonic() + duration
            next_interaction = time.monotonic() + 4
            while time.monotonic() < end:
                self.check_cancel(job_id)
                if profile.get("interaction") and time.monotonic() >= next_interaction:
                    try:
                        vm.interact(seed=int(job_id[:8], 16) + int(time.monotonic()))
                    except Exception as exc:
                        run.setdefault("warnings", []).append("Interazione desktop parziale: " + str(exc)[:120])
                        next_interaction = end + 1
                    else:
                        next_interaction = time.monotonic() + 15
                self.stopping.wait(1)
            try:
                vm.screenshot(collected / "desktop-after.png")
            except Exception as exc:
                run.setdefault("warnings", []).append("Screenshot finale non raccolto: " + str(exc)[:120])
        except Cancelled:
            cancelled = True
        finally:
            try:
                if launched and not self.stopping.is_set():
                    rc, stdout, stderr = vm.exec(base_command + " -Mode finish", timeout=400)
                    if rc:
                        run.setdefault("warnings", []).append("Raccolta finale parziale: " + (stderr or stdout)[-400:])
                    for name, kind in GUEST_ARTIFACTS.items():
                        try:
                            limit = 1024 * 1024 if name == "payloads.json" else 512 * 1024 * 1024 if name.endswith(".pml") else 256 * 1024 * 1024 if name.endswith(".etl") else 192 * 1024 * 1024 if name in {"telemetry.json", "baseline-before.json", "baseline-after.json"} else 128 * 1024 * 1024 if name.endswith((".evtx", "_events.jsonl")) else 64 * 1024 * 1024
                            vm.pull(guest_dir + "\\" + name, collected / name, max_bytes=limit)
                        except Exception as exc:
                            if name == "telemetry.json":
                                run.setdefault("warnings", []).append("Telemetria non raccolta: " + str(exc)[:250])
                            elif profile.get("kernel") and name in {"kernel.etl", "kernel_events.jsonl"}:
                                run.setdefault("warnings", []).append(f"Artefatto kernel non acquisito ({name}): " + str(exc)[:250])
                    from lab.payloads import payload_artifact_candidates
                    payload_budget = 64 * 1024 * 1024
                    for name in payload_artifact_candidates(collected):
                        try:
                            if payload_budget <= 0:
                                run.setdefault("warnings", []).append("Budget aggregato payload secondari (64 MiB) raggiunto.")
                                break
                            vm.pull(guest_dir + "\\" + name, collected / name, max_bytes=min(16 * 1024 * 1024, payload_budget))
                            payload_budget -= (collected / name).stat().st_size
                        except Exception as exc:
                            run.setdefault("warnings", []).append("Payload secondario non acquisito: " + str(exc)[:180])
            except Exception as exc:
                run.setdefault("warnings", []).append("Export guest non completo: " + str(exc)[:300])
            finally:
                try:
                    vm.stop()
                finally:
                    try:
                        for name in ("network.pcap", "namespace.json", "privacy.json", "http.jsonl", "interaction.json", "vm.json", "qemu.log", "egress-policy.json", "egress-final-policy.json", "egress-request.json", "egress-ready.json", "egress-resolv.conf", "egress.log"):
                            source = runtime / name
                            if source.is_file() and not source.is_symlink() and source.stat().st_size <= 1024 * 1024 * 1024:
                                shutil.copy2(source, out / name)
                        if collected.is_dir() and not collected.is_symlink():
                            for source in collected.iterdir():
                                if source.is_file() and not source.is_symlink() and source.stat().st_size <= 512 * 1024 * 1024:
                                    shutil.copy2(source, out / source.name)
                    finally:
                        try:
                            vm.cleanup()
                        finally:
                            self.active_vm = None
        from lab.payloads import read_payloads
        payloads = read_payloads(out)
        verified_payloads = set(payloads.get("artifact_names", []))
        for path in sorted(out.iterdir()):
            kind = GUEST_ARTIFACTS.get(path.name, "pcap" if path.suffix == ".pcap" else "payload" if path.name.startswith("payload-") and path.suffix == ".bin" else "screenshot" if path.suffix == ".png" else "runtime")
            if artifact := self.artifact(job_id, path, kind, profile["id"], verified_payloads=verified_payloads):
                added.append(artifact)
        if cancelled:
            run.update(status="cancelled", finished_at=utcnow(), artifacts=added)
            self.store.update(job_id, runs=runs, artifacts=self.store.get(job_id).get("artifacts", []) + added)
            raise Cancelled()
        raw = read_json(out / "telemetry.json", {}, max_bytes=192 * 1024 * 1024)
        if not raw:
            from lab.recovery import recover
            raw = recover(out)
        if raw:
            from lab.baseline import compare
            before = read_json(out / "baseline-before.json", {}, max_bytes=192 * 1024 * 1024)
            after = read_json(out / "baseline-after.json", {}, max_bytes=192 * 1024 * 1024)
            if before and after:
                raw["changes"] = compare(before, after)
            else:
                raw.setdefault("warnings", []).append("Confronto baseline non disponibile: uno snapshot non è stato raccolto.")
        if raw and (out / "procmon.csv").exists():
            from lab.telemetry import read_procmon
            raw["procmon"] = read_procmon(out / "procmon.csv")
        api_events = []
        api_path = out / "api.jsonl"
        if api_path.exists() and api_path.stat().st_size <= 64 * 1024 * 1024:
            with api_path.open(encoding="utf-8-sig") as stream:
                for line in stream:
                    if len(api_events) >= 50000:
                        break
                    try:
                        api_events.append(json.loads(line))
                    except ValueError:
                        continue
        dynamic = normalize(raw, api_events=api_events)
        dynamic["privacy"] = read_json(out / "privacy.json", {"status": "unverified", "verified": False})
        if profile.get("kernel"):
            from lab.kernel import read_kernel
            from lab.telemetry import attach_kernel
            dynamic = attach_kernel(dynamic, read_kernel(out), requested=True)
        dynamic["payloads"] = payloads
        dynamic.setdefault("warnings", []).extend(dynamic["payloads"].get("warnings", []))
        from lab.drivers import enrich
        dynamic = enrich(dynamic, self.settings.tools)
        dynamic["pcap"] = summarize(out / "network.pcap")
        dynamic["isolation"] = read_json(out / "namespace.json", {})
        dynamic["elastic"] = elastic_lookup(self.store.get(job_id)["sha256"], run["started_at"], utcnow())
        status = "completed" if raw else "failed"
        launch = raw.get("launch", {}) if isinstance(raw, dict) else {}
        if launch.get("status") in {"blocked", "quarantined", "denied"}:
            status = "blocked"
        elif launch.get("status") in {"error", "unavailable", "unsupported"}:
            status = "failed"
            run.setdefault("warnings", []).append("Sample non avviato: " + str(launch.get("detail", launch.get("status")))[:250])
        elif raw.get("recovered") or raw.get("truncated") or dynamic.get("coverage", {}).get("truncated") or dynamic.get("payloads", {}).get("status") in {"partial", "error", "untrusted"} or any(isinstance(sensor, dict) and sensor.get("status") in {"error", "partial"} or (name == "kernel" and profile.get("kernel") and isinstance(sensor, dict) and sensor.get("status") == "unavailable") for name, sensor in dynamic.get("capabilities", {}).items()):
            status = "partial"
        run.update(status=status, dynamic=dynamic, artifacts=added, finished_at=utcnow())
        self.store.replace_events(job_id, profile["id"], dynamic.get("events", []))
        run["_events_indexed"] = True
        if not raw:
            run.setdefault("warnings", []).append("Nessuna telemetria dinamica disponibile; esito non valutabile.")
        return run, added

    @staticmethod
    def make_summary(static, runs):
        findings = []
        av = static.get("av", {})
        if isinstance(av, dict) and (av.get("result") or {}).get("infected") is True:
            findings.append({"id": "av:clamav", "severity": "high", "title": "Rilevamento del motore ClamAV",
                             "description": ", ".join((av.get("result") or {}).get("detections", [])),
                             "source": "clamav", "evidence_ids": ["static:av"]})
        for run in runs:
            for finding in run.get("dynamic", {}).get("findings", []):
                findings.append({**finding, "profile": run["profile"]})
        return {"verdict": "review_required" if findings else "no_automatic_verdict", "findings": findings[:300],
                "completed_runs": sum(run["status"] in {"completed", "blocked"} for run in runs),
                "total_runs": len(runs), "detail": "Osservazioni e verdetti dei sensori, non garanzia di innocuità. La policy di rete effettiva è riportata per ciascuna esecuzione."}


def public_job(job):
    """Drop internal filesystem paths everywhere, including nested artifacts."""
    def clean(value):
        if isinstance(value, dict):
            return {key: clean(item) for key, item in value.items() if not key.startswith("_")}
        if isinstance(value, list):
            return [clean(item) for item in value]
        return value
    return clean(job)


def redacted_share(job):
    static = job.get("static", {})
    statuses = {"available", "completed", "partial", "failed", "error", "unavailable", "disabled", "blocked", "unknown", "cancelled"}
    def safe_status(value):
        return value if isinstance(value, str) and value in statuses else "unknown"
    runs = []
    for run in job.get("runs", []):
        dynamic = run.get("dynamic", {})
        counts = {name: value for name, value in dynamic.get("counts", {}).items()
                  if name in {"events", "related_events", "processes", "related_processes", "api_calls", "kernel_events", "kernel_syscalls", "kernel_stacks"} and type(value) is int and value >= 0}
        caps = {name: {"status": safe_status(value.get("status"))} for name, value in dynamic.get("capabilities", {}).items()
                if name in {"sysmon", "procmon", "defender", "frida", "dtrace", "kernel"} and isinstance(value, dict)}
        runs.append({"profile": run["profile"], "profile_name": run.get("profile_name"), "status": run["status"],
                     "dynamic": {"counts": counts, "capabilities": caps,
                                 "defender": {"status": safe_status(dynamic.get("defender", {}).get("status")), "detail": "Dettagli privati omessi"}}})
    return {"id": job["id"], "name": "Sample " + job["sha256"][:12], "sha256": job["sha256"], "status": job["status"], "created_at": job["created_at"],
            "static": {"hashes": static.get("hashes", {}), "size": static.get("size"), "type": static.get("type")},
            "runs": runs,
            "summary": {"verdict": job.get("summary", {}).get("verdict", "not_evaluated"), "detail": "Report condiviso ridotto: niente sample, percorsi, comandi, eventi grezzi o PCAP."},
            "warnings": ["Link bearer in sola lettura, revocabile e con scadenza. Non inoltrarlo a chi non deve vedere il riepilogo. Il tunnel gratuito usa un indirizzo temporaneo."]}

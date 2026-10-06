"""Static evidence collection with fail-closed, networkless bubblewrap isolation.

Only bounded hashing is performed in the supervisor. Sample parsers and engines
run on read-only mounts in separate user/PID/network namespaces. No sample is
executed. Absence of evidence is never returned as a clean verdict.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

MAX_SAMPLE = 100 * 1024 * 1024
MAX_STDOUT = 8 * 1024 * 1024
MAX_STDERR = 256 * 1024
MEMORY_LIMIT = 2 * 1024 * 1024 * 1024
TMP_LIMIT = 64 * 1024 * 1024
RULES = Path(__file__).parent / "rules"
WORKER = Path(__file__).with_name("static_worker.py")
PARSER_TIMEOUT = 75
TOOL_TIMEOUT = 120


def _status(state: str, detail: str, result=None) -> dict:
    return {"status": state, "detail": detail, "result": result}


def _env_executable(tools: Path, component: str, name: str) -> Path | None:
    path = tools / component / "bin" / name
    return path.absolute() if path.is_file() and os.access(path, os.X_OK) else None


def _static_python(tools: Path) -> Path:
    return _env_executable(tools, "static", "python") or Path(sys.executable).absolute()


def _module_present(tools: Path, name: str) -> bool:
    if _env_executable(tools, "static", "python"):
        return any((tools / "static" / "lib").glob("python*/site-packages/" + name + "*"))
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def _clam_database(tools: Path) -> Path | None:
    for directory in (tools / "clamav", Path("/var/lib/clamav")):
        if directory.is_dir() and any(file.is_file() and file.stat().st_size > 0 for pattern in ("*.cvd", "*.cld") for file in directory.glob(pattern)):
            return directory.absolute()
    return None


def capabilities(tools: Path) -> dict:
    """Detect locally installed engines; namespace usability is verified per job."""
    tools = tools.absolute()
    bwrap, prlimit = shutil.which("bwrap"), shutil.which("prlimit")
    isolation = bool(bwrap and prlimit)
    sandbox = _status("available" if isolation else "unavailable", "Bubblewrap e prlimit rilevati; accesso ai namespace verificato a ogni esecuzione" if isolation else "Bubblewrap e prlimit obbligatori; nessun fallback non isolato", {"backend": "bubblewrap", "bwrap": bwrap, "prlimit": prlimit, "network": False, "sample_read_only": True, "runtime_read_only": True, "private_tmp_max_bytes": TMP_LIMIT, "memory_max_bytes": MEMORY_LIMIT, "output_max_bytes": MAX_STDOUT, "verified": False})
    result = {"sandbox": sandbox}
    for label, module in (("pe", "pefile"), ("yara", "yara")):
        found = _module_present(tools, module)
        result[label] = _status("available" if found and isolation else "unavailable", "Modulo rilevato nell'ambiente statico" if found and isolation else ("Isolamento obbligatorio non disponibile" if not isolation else module + " non installato"), {"python": str(_static_python(tools))})
    result["strings"] = _status("available" if isolation else "unavailable", "Parser ASCII/UTF-16 isolato e limitato" if isolation else "Isolamento obbligatorio non disponibile")
    for component in ("floss", "capa"):
        executable = _env_executable(tools, component, component)
        rules_found = (tools / "capa-rules").is_dir() and (tools / "capa-sigs").is_dir() if component == "capa" else True
        available = bool(executable and isolation and rules_found)
        detail = "Ambiente uv indipendente rilevato" if available else ("Isolamento obbligatorio non disponibile" if not isolation else ("Regole o firme FLIRT capa locali assenti" if executable and not rules_found else "Ambiente uv indipendente assente"))
        result[component] = _status("available" if available else "unavailable", detail, {"path": str(executable) if executable else None})
    clam = shutil.which("clamscan")
    database = _clam_database(tools)
    result["clamav"] = _status("available" if clam and database and isolation else "unavailable", "Motore ClamAV e database locali rilevati; validità verificata durante la scansione" if clam and database and isolation else "ClamAV, firme locali e isolamento obbligatori", {"path": clam, "database": str(database) if database else None})
    cache = tools / "loldrivers.json"
    result["loldrivers"] = _status("available" if cache.is_file() and isolation else "unavailable", "Cache hash locale rilevata; nessun download di driver" if cache.is_file() and isolation else "Cache LOLDrivers locale o isolamento assenti", {"path": str(cache) if cache.is_file() else None})
    reputation_enabled = os.environ.get("SANDBOX_VT_HASH_LOOKUP") == "1" and bool(os.environ.get("VT_API_KEY"))
    result["virustotal"] = _status("available" if reputation_enabled else "unavailable", "Reputazione hash abilitata esplicitamente; comunica SHA-256, mai il campione" if reputation_enabled else "Disabilitato: richiede SANDBOX_VT_HASH_LOOKUP=1 e VT_API_KEY; nessun upload", {"enabled": reputation_enabled, "uploads": False})
    return result


def _runtime_roots(executable: Path, tools: Path) -> list[Path]:
    roots = []
    # Mount only this tool's venv and its resolved interpreter installation,
    # never the home directory or the host root.
    for component in ("static", "floss", "capa"):
        root = (tools / component).absolute()
        if executable.is_relative_to(root):
            roots.append(root)
            python = root / "bin" / "python"
            if python.exists():
                resolved = python.resolve()
                if not resolved.is_relative_to(Path("/usr")):
                    roots.append(resolved.parent.parent)
    current = Path(sys.prefix).absolute()
    if executable.is_relative_to(current) and current not in (Path("/"), Path("/usr")):
        roots.append(current)
    resolved = executable.resolve()
    if not resolved.is_relative_to(Path("/usr")) and resolved.name.startswith("python"):
        roots.append(resolved.parent.parent)
    unique = []
    for root in sorted(set(roots), key=lambda path: len(path.parts)):
        if root == Path("/") or root == Path.home():
            raise ValueError("Radice runtime troppo ampia per l'isolamento")
        if root.exists() and not any(root.is_relative_to(parent) for parent in unique):
            unique.append(root)
    return unique


def _sandbox_command(sample: Path, tools: Path, executable: Path, arguments: list[str], timeout: int, mounts: list[tuple[Path, str]], writable_tmp: bool = False) -> list[str]:
    bwrap, prlimit = shutil.which("bwrap"), shutil.which("prlimit")
    if not bwrap or not prlimit:
        raise RuntimeError("Isolamento non disponibile: bwrap/prlimit obbligatori")
    command = [prlimit, "--as=" + str(MEMORY_LIMIT), "--cpu=" + str(timeout + 5), "--nofile=128", "--fsize=16777216", "--core=0", "--", bwrap, "--unshare-all", "--unshare-net", "--die-with-parent", "--new-session", "--cap-drop", "ALL", "--clearenv", "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "HOME", "/tmp", "--setenv", "TMPDIR", "/tmp", "--setenv", "LANG", "C.UTF-8", "--setenv", "PYTHONNOUSERSITE", "1", "--setenv", "PYTHONDONTWRITEBYTECODE", "1"]
    for name in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS"):
        command += ["--setenv", name, "1"]
    command += ["--setenv", "CAPA_SAVE_WORKSPACE", "0", "--setenv", "FLOSS_SAVE_WORKSPACE", "0", "--setenv", "USER", "analyst", "--setenv", "LOGNAME", "analyst"]
    for system in ("/usr", "/bin", "/lib", "/lib64"):
        if Path(system).exists():
            command += ["--ro-bind", system, system]
    for configuration in ("/etc/ld.so.cache", "/etc/localtime"):
        if Path(configuration).is_file():
            command += ["--ro-bind", configuration, configuration]
    for root in _runtime_roots(executable, tools):
        command += ["--ro-bind", str(root), str(root)]
    command += ["--proc", "/proc", "--remount-ro", "/proc", "--dev", "/dev", "--size", str(TMP_LIMIT), "--tmpfs", "/tmp"]
    if not writable_tmp:
        command += ["--remount-ro", "/tmp"]
    command += ["--dir", "/app", "--dir", "/sample", "--ro-bind", str(sample), "/sample/input"]
    for source, destination in mounts:
        command += ["--ro-bind", str(source.absolute()), destination]
    # Apply the process budget after entering the private user/PID namespace,
    # otherwise the host user's already-running desktop processes exhaust it.
    command += ["--remount-ro", "/", "--chdir", "/tmp", "--", prlimit, "--nproc=64", "--", str(executable), *arguments]
    return command


def _stop(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.kill()
    except ProcessLookupError:
        pass
    process.wait(timeout=5)


def _run(command: list[str], timeout: int, accepted_codes=(0,)) -> dict:
    started = time.monotonic()
    stdout, stderr = bytearray(), bytearray()
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, close_fds=True, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    except OSError as exc:
        return _status("error", "Avvio dell'isolamento fallito: " + str(exc)[:512])
    state, detail = "completed", "Strumento eseguito nel sandbox isolato"
    selector = selectors.DefaultSelector()
    try:
        for stream, label in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        while selector.get_map():
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                state, detail = "timeout", "Tempo massimo dello strumento superato"
                _stop(process)
                break
            for key, _ in selector.select(timeout=min(remaining, 0.25)):
                try:
                    chunk = os.read(key.fd, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target = stdout if key.data == "stdout" else stderr
                limit = MAX_STDOUT if key.data == "stdout" else MAX_STDERR
                if len(target) + len(chunk) > limit:
                    target.extend(chunk[:max(0, limit - len(target))])
                    state, detail = "error", "Limite di output superato; strumento terminato"
                    _stop(process)
                    break
                target.extend(chunk)
            if state != "completed":
                break
        if process.poll() is None:
            remaining = max(0.01, timeout - (time.monotonic() - started))
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                state, detail = "timeout", "Tempo massimo dello strumento superato"
                _stop(process)
        if state == "completed" and process.returncode not in accepted_codes:
            state, detail = "error", "Strumento o isolamento fallito (codice " + str(process.returncode) + ")"
        if state == "completed" and (stderr.startswith(b"bwrap:") or stderr.startswith(b"prlimit:")):
            state, detail = "error", "Isolamento non avviato: " + stderr.decode("utf-8", "replace")[:300]
        return _status(state, detail, {"returncode": process.returncode, "stdout": stdout.decode("utf-8", errors="replace"), "stderr": stderr.decode("utf-8", errors="replace"), "duration_seconds": round(time.monotonic() - started, 3), "output_truncated": detail.startswith("Limite di output")})
    finally:
        selector.close()
        if process.poll() is None:
            _stop(process)
        process.stdout.close()
        process.stderr.close()


def _isolated(sample: Path, tools: Path, executable: Path, arguments: list[str], timeout: int, mounts=None, accepted_codes=(0,), writable_tmp=False) -> dict:
    try:
        command = _sandbox_command(sample, tools, executable, arguments, timeout, mounts or [], writable_tmp)
    except (RuntimeError, ValueError, OSError) as exc:
        return _status("unavailable", str(exc)[:512])
    return _run(command, timeout, accepted_codes)


def _json_tool(run: dict, name: str) -> dict:
    if run["status"] != "completed":
        return _status(run["status"], name + ": " + run["detail"], {"stderr": (run.get("result") or {}).get("stderr", "")[:4096]})
    try:
        payload = json.loads(run["result"]["stdout"])
        if not isinstance(payload, dict):
            raise ValueError("JSON radice non è un oggetto")
        return _status("completed", name + " completato nel sandbox; risultati statici, non verdetto", payload)
    except (ValueError, RecursionError) as exc:
        return _status("error", name + ": output JSON non valido: " + str(exc)[:256], {"stderr": run["result"]["stderr"][:4096]})


def _clamav(sample: Path, tools: Path, cap: dict) -> dict:
    if cap["status"] != "available":
        return _status("unavailable", cap["detail"])
    options = ["--stdout", "--database=/db", "--max-filesize=100M", "--max-scansize=200M", "--max-recursion=8", "--max-files=500", "--max-scantime=60000", "--alert-exceeds-max=yes", "/sample/input"]
    run = _isolated(sample, tools, Path(cap["result"]["path"]), options, 90, [(Path(cap["result"]["database"]), "/db")], accepted_codes=(0, 1), writable_tmp=True)
    if run["status"] != "completed":
        return _status(run["status"], "ClamAV: " + run["detail"], {"stderr": (run.get("result") or {}).get("stderr", "")[:4096], "stdout": (run.get("result") or {}).get("stdout", "")[:4096]})
    output = run["result"]["stdout"]
    detections = [line.rsplit(": ", 1)[-1].removesuffix(" FOUND") for line in output.splitlines() if line.endswith(" FOUND")][:100]
    engine = next((line.split(":", 1)[-1].strip() for line in output.splitlines() if line.startswith("Engine version:")), None)
    limits_exceeded = any("Limits.Exceeded" in name for name in detections)
    scan_error = " ERROR" in output or "Can't open" in output or "Can't create" in output or (not output.strip()) or (run["result"]["returncode"] == 1 and not detections)
    non_limit_detections = [name for name in detections if "Limits.Exceeded" not in name]
    infected = True if non_limit_detections else (None if limits_exceeded or scan_error else False)
    result = {"infected": infected, "detections": detections, "engine": "ClamAV", "engine_version": engine, "database": cap["result"]["database"], "limits_exceeded": limits_exceeded, "scan_complete": not (limits_exceeded or scan_error), "output": output[:8192], "stderr": run["result"]["stderr"][:4096], "note": "Nessun rilevamento non significa file sicuro; scansione locale con limiti su archivi, tempo e dimensione."}
    return _status("error" if scan_error or limits_exceeded else "completed", "ClamAV: scansione incompleta" if scan_error or limits_exceeded else "Scansione locale ClamAV completata; nessun upload", result)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _hash_reputation(sha256: str) -> dict:
    if os.environ.get("SANDBOX_VT_HASH_LOOKUP") != "1" or not os.environ.get("VT_API_KEY"):
        return _status("unavailable", "Reputazione esterna disabilitata; nessun hash o file inviato", {"enabled": False, "uploads": False})
    request = Request("https://www.virustotal.com/api/v3/files/" + sha256, headers={"x-apikey": os.environ["VT_API_KEY"], "Accept": "application/json"})
    try:
        opener = build_opener(ProxyHandler({}), _NoRedirect())
        with opener.open(request, timeout=15) as response:
            raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError("Risposta oltre il limite di 1 MiB")
        attributes = json.loads(raw).get("data", {}).get("attributes", {})
        return _status("completed", "Solo reputazione SHA-256; il campione non è stato caricato", {"provider": "VirusTotal", "sha256": sha256, "uploads": False, "stats": attributes.get("last_analysis_stats", {}), "last_analysis_date": attributes.get("last_analysis_date"), "meaningful_name": attributes.get("meaningful_name"), "note": "Reputazione esterna preesistente, non analisi del campione né garanzia di sicurezza."})
    except HTTPError as exc:
        return _status("completed" if exc.code == 404 else "error", "Hash non presente su VirusTotal; nessun upload" if exc.code == 404 else "Reputazione hash non disponibile (HTTP " + str(exc.code) + ")", {"provider": "VirusTotal", "known": False if exc.code == 404 else None, "uploads": False})
    except Exception as exc:
        return _status("error", "Reputazione hash: " + str(exc)[:256], {"uploads": False})


def _hash_sample(path: Path) -> tuple[int, dict]:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("Il campione deve essere un file regolare, non un link o dispositivo")
        if metadata.st_size > MAX_SAMPLE:
            raise ValueError("Campione oltre il limite di 100 MiB")
        hashes = {name: hashlib.new(name, usedforsecurity=False) for name in ("md5", "sha1", "sha256")}
        total = 0
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            while chunk := stream.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_SAMPLE:
                    raise ValueError("Campione cresciuto oltre il limite")
                for value in hashes.values():
                    value.update(chunk)
        if total != metadata.st_size:
            raise ValueError("Il campione è cambiato durante l'hashing")
        return total, {name: value.hexdigest() for name, value in hashes.items()}
    finally:
        os.close(descriptor)


def _save_result(artifacts: Path, payload: dict) -> None:
    artifacts.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".static-", dir=artifacts)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=True, separators=(",", ":"))
        os.chmod(temporary, 0o600)
        os.replace(temporary, artifacts / "static.json")
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def analyze(sample: Path, artifacts: Path, tools: Path) -> dict:
    """Return static evidence directly consumable by the API and Italian UI."""
    sample, tools = sample.absolute(), tools.absolute()
    caps = capabilities(tools)
    missing = _status("unavailable", "Analisi non eseguita; nessun verdetto di sicurezza")
    result = {"hashes": {}, "size": None, "type": {"description": "Non identificato", "mime": "application/octet-stream", "extension": sample.suffix.lower(), "executable": False}, "pe": dict(missing), "strings": dict(missing), "iocs": dict(missing), "yara": dict(missing), "capa": dict(missing), "floss": dict(missing), "av": dict(missing), "byovd": dict(missing), "capabilities": caps, "warnings": [], "reputation": _status("unavailable", "Reputazione esterna disabilitata; nessun upload")}
    try:
        result["size"], result["hashes"] = _hash_sample(sample)
    except (OSError, ValueError) as exc:
        result["warnings"].append("Campione non analizzabile: " + str(exc)[:512])
        return result
    mounts = [(WORKER, "/app/static_worker.py"), (RULES, "/rules")]
    arguments = ["/app/static_worker.py", "--sample", "/sample/input", "--name", sample.name, "--rules", "/rules"]
    if (tools / "loldrivers.json").is_file():
        mounts.append((tools / "loldrivers.json", "/loldrivers.json"))
        arguments += ["--loldrivers", "/loldrivers.json"]
    run = _isolated(sample, tools, _static_python(tools), arguments, PARSER_TIMEOUT, mounts)
    parsed = _json_tool(run, "Parser statici")
    if parsed["status"] == "completed" and "fatal" not in parsed["result"]:
        for key in ("type", "pe", "strings", "iocs", "yara", "byovd"):
            if key in parsed["result"]:
                result[key] = parsed["result"][key]
        caps["sandbox"]["result"]["verified"] = True
    else:
        detail = (parsed.get("result") or {}).get("fatal", parsed["detail"])
        result["warnings"].append(detail)
        for key in ("pe", "strings", "iocs", "yara", "byovd"):
            result[key] = _status("error" if parsed["status"] == "completed" else parsed["status"], detail)
    is_pe = result["pe"]["status"] == "completed"
    for component, options in (("floss", ["--json", "--quiet", "/sample/input"]), ("capa", ["--json", "--quiet", "--rules", "/rules-capa", "--signatures", "/signatures-capa", "/sample/input"])):
        cap = caps[component]
        if cap["status"] != "available":
            result[component] = _status("unavailable", cap["detail"])
        elif not is_pe:
            result[component] = _status("unavailable", "Non applicabile: PE valido non identificato; nessuna esecuzione del campione")
        else:
            extra_mounts = [(tools / "capa-rules", "/rules-capa"), (tools / "capa-sigs", "/signatures-capa")] if component == "capa" else []
            # Both vivisect tools need scratch/cache, confined to disposable 64MiB tmpfs.
            # The sample, runtime, rules, signatures and host root remain read-only.
            result[component] = _json_tool(_isolated(sample, tools, Path(cap["result"]["path"]), options, TOOL_TIMEOUT, extra_mounts, writable_tmp=True), component.upper())
    result["av"] = _clamav(sample, tools, caps["clamav"])
    result["reputation"] = _hash_reputation(result["hashes"]["sha256"])
    for key in ("pe", "strings", "iocs", "yara", "capa", "floss", "av", "byovd"):
        evidence = result[key]
        if evidence["status"] in {"error", "timeout"}:
            result["warnings"].append(key + ": " + evidence["detail"])
    result["warnings"].append("Analisi statica: assenza di rilevamenti non equivale a sicurezza; firme PE non verificate e indicatori BYOVD non dimostrano sfruttamento.")
    try:
        _save_result(artifacts, result)
    except OSError as exc:
        result["warnings"].append("Salvataggio static.json fallito: " + str(exc)[:256])
    return result

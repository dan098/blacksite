"""Extract a cold clean-base snapshot, then provision an isolated disposable clone.

CLI phases are deliberately separate: extraction needs no guest collector files.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid

from .config import PROFILES
from .privacy import validate_privacy_proof
from .vm import AnalysisVM, VMError, _json_write, _private_dir

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASE = ROOT / "data/bases"
SIDECARS = ("OVMF_VARS.fd", "tpm2-00.permall")
KERNEL_ASSETS = ("kernel.wprp", "kernel_decode.cs")
REQUIRED_GUEST = (
    "privacy.ps1", "setup.ps1", "prepare.ps1", "baseline.ps1", "collect.ps1",
    "launch.ps1", "sysmon.xml", "kernel_trace.ps1", *KERNEL_ASSETS,
)


def _source_signature(source: Path) -> dict:
    return {name: {"size": (source / name).stat().st_size, "mtime_ns": (source / name).stat().st_mtime_ns,
                   "inode": (source / name).stat().st_ino}
            for name in ("disk.qcow2", *SIDECARS)}


def assert_source_off(source: Path) -> None:
    """Read-only check. Never stop the source or obtain a writable source handle."""
    source = source.resolve()
    for process in Path("/proc").iterdir():
        if not process.name.isdigit():
            continue
        try:
            argv = (process / "cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", "replace")
            if not any(name in argv for name in ("qemu-system", "swtpm")):
                continue
            if str(source) in argv or source.name in argv:
                raise VMError("La VM sorgente o il suo TPM è attivo. Spegnerla manualmente prima del bootstrap")
            for descriptor in (process / "fd").iterdir():
                with contextlib.suppress(FileNotFoundError, PermissionError, OSError):
                    target = Path(os.readlink(descriptor))
                    if target.is_absolute() and target.is_relative_to(source):
                        raise VMError("Un processo QEMU/TPM usa la sorgente: bootstrap rifiutato")
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue


@contextlib.contextmanager
def bootstrap_lock(base_dir: Path):
    _private_dir(base_dir.parent)
    fd = os.open(base_dir.parent / ".bootstrap.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a+") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise VMError("Un altro bootstrap è già in corso") from exc
        try:
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _run(command: list[str], timeout=1800) -> bytes:
    """All helper process groups are reaped even on timeout/cancellation."""
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    try:
        out, err = process.communicate(timeout=timeout)
        if process.returncode:
            raise VMError(f"{Path(command[0]).name}: " + err.decode("utf-8", "replace")[:4096])
        return out
    finally:
        AnalysisVM._kill_group(process)


def _stage(base_dir: Path) -> Path:
    return base_dir.parent / f".{base_dir.name}-extracted"


def extract(source: Path, base_dir: Path, snapshot: str, snapshots_dir: Path) -> dict:
    source, base_dir = source.resolve(), base_dir.resolve()
    if base_dir == source or base_dir.is_relative_to(source) or source.is_relative_to(base_dir):
        raise VMError("Directory sorgente e base devono essere separate")
    if not snapshot or any(char in snapshot for char in ("/", "\\", "\x00", ",", "\n", "\r")):
        raise VMError("Nome snapshot non valido")
    assert_source_off(source)
    signature = _source_signature(source)
    stage = _stage(base_dir)
    if stage.exists():
        try:
            previous = json.loads((stage / "metadata.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise VMError(f"Estrazione incompleta presente: {stage}. Conservarla o rimuoverla manualmente, poi riprovare") from exc
        if previous.get("snapshot") == snapshot and previous.get("source_signature") == signature and (stage / "clean.qcow2").is_file():
            return {"status": "already_extracted", "stage": str(stage), "snapshot": snapshot}
        raise VMError("Estrazione esistente diversa dalla sorgente; nessuna sovrascrittura automatica")
    if (base_dir / "metadata.json").exists():
        existing = json.loads((base_dir / "metadata.json").read_text(encoding="utf-8"))
        if existing.get("ready"):
            return {"status": "already_ready", "base_dir": str(base_dir)}
    info = json.loads(_run(["qemu-img", "info", "--output=json", str(source / "disk.qcow2")], timeout=30))
    if info.get("format") != "qcow2" or snapshot not in [item.get("name") for item in info.get("snapshots", [])]:
        raise VMError(f"Snapshot interno {snapshot!r} non presente nella sorgente qcow2")
    side = snapshots_dir.resolve() / snapshot
    for name in SIDECARS:
        if not (side / name).is_file() or (side / name).is_symlink():
            raise VMError(f"Sidecar coerente con lo snapshot mancante: {side / name}")
    stage.mkdir(mode=0o700)
    source_copy = stage / f"source-{uuid.uuid4().hex}.qcow2"
    # cp reflink auto is copy-on-write when supported, a sparse full copy otherwise.
    _run(["cp", "--reflink=auto", "--sparse=always", "--", str(source / "disk.qcow2"), str(source_copy)])
    source_copy.chmod(0o600)
    assert_source_off(source)
    if _source_signature(source) != signature:
        raise VMError("Sorgente cambiata durante la copia; estrazione non utilizzabile")
    _run(["qemu-img", "convert", "-l", f"snapshot.name={snapshot}", "-O", "qcow2",
          str(source_copy), str(stage / "clean.qcow2")])
    (stage / "clean.qcow2").chmod(0o600)
    for name in SIDECARS:
        shutil.copyfile(side / name, stage / name)
        (stage / name).chmod(0o600)
    assert_source_off(source)
    if _source_signature(source) != signature:
        raise VMError("Sorgente cambiata durante l'estrazione; base non pubblicata")
    metadata = {"ready": False, "phase": "extracted", "snapshot": snapshot, "source": str(source),
                "source_signature": signature, "extracted_at": time.time(), "os": "Windows 11",
                "capabilities": {}, "warnings": ["Collector non ancora provisionati"]}
    _json_write(stage / "metadata.json", metadata)
    source_copy.unlink()
    return {"status": "extracted", "stage": str(stage), "snapshot": snapshot,
            "next": "Eseguire la fase provision quando guest/setup.ps1 e collector sono disponibili"}


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _validate_guest(guest_dir: Path) -> None:
    for name in REQUIRED_GUEST:
        path = guest_dir / name
        if not path.is_file() or path.is_symlink():
            raise VMError(f"Collector richiesto non disponibile: {name}; estrazione preservata")
    pinned = ROOT / "guest/privacy.ps1"
    if (pinned.is_symlink() or not pinned.is_file()
            or (guest_dir / "privacy.ps1").read_bytes() != pinned.read_bytes()):
        raise VMError("Il provisionamento richiede lo script privacy fidato del repository")


def _upload_guest(vm: AnalysisVM, guest_dir: Path, tool_dir: Path, install_frida: bool) -> bool:
    _validate_guest(guest_dir)
    rc, out, err = vm.exec("$ErrorActionPreference='Stop'; New-Item -ItemType Directory -Force -Path 'C:\\Sandbox\\tools','C:\\Sandbox\\tools\\frida-wheels' | Out-Null")
    if rc:
        raise VMError("Creazione directory collector fallita: " + err[:1024])
    allowed = {".ps1", ".xml", ".py", ".js", ".json"}
    for path in sorted(guest_dir.iterdir()):
        # start() already uploaded and verified the pinned enforcer before public push.
        if (path.name.lower() != "privacy.ps1" and path.is_file() and not path.is_symlink()
                and (path.suffix.lower() in allowed or path.name in KERNEL_ASSETS)):
            vm.push(path, "C:\\Sandbox\\tools\\" + path.name)
    offline = tool_dir / "guest"
    if offline.is_dir():
        for name in ("uv.exe", "Sysmon64.exe", "Procmon64.exe"):
            path = offline / name
            if path.is_file():
                vm.push(path, "C:\\Sandbox\\tools\\" + name)
    wheels = sorted((offline / "frida-wheels").glob("*.whl")) if offline.is_dir() else []
    frida_available = install_frida and (offline / "uv.exe").is_file() and bool(wheels)
    if frida_available:
        if len(wheels) > 20:
            raise VMError("Troppi wheel offline; limite 20")
        for path in wheels:
            vm.push(path, "C:\\Sandbox\\tools\\frida-wheels\\" + path.name)
    return frida_available


def _verify_network(vm: AnalysisVM) -> dict:
    # Numeric endpoints only, without DNS; no packet can escape the required netns.
    ps = r"""
$ErrorActionPreference='Stop'
$result = [ordered]@{}
foreach($entry in @(@('host','10.0.2.2',8765),@('lan','192.168.1.1',80),@('internet','1.1.1.1',443))) {
  $c = New-Object Net.Sockets.TcpClient
  try {
    $task=$c.ConnectAsync([string]$entry[1],[int]$entry[2])
    $connected=$false
    try { if($task.Wait(1000)) {$connected=$c.Connected} } catch {$connected=$false}
    $result[[string]$entry[0]] = -not $connected
  } finally { $c.Dispose() }
}
try {
  $http=Invoke-WebRequest -Uri 'http://10.0.2.100/' -UseBasicParsing -TimeoutSec 8
  $result['synthetic_http']=($http.StatusCode -eq 200 -and $http.Content -match 'Sandbox locale')
} catch { $result['synthetic_http']=$false; $result['http_error']=$_.Exception.Message }
$result | ConvertTo-Json -Compress
"""
    rc, out, err = vm.exec(ps, timeout=30)
    if rc:
        raise VMError("Verifica rete guest fallita: " + err[:1024])
    try:
        evidence = json.loads(out.strip().lstrip("\ufeff"))
    except ValueError as exc:
        raise VMError("Risultato verifica rete guest non valido") from exc
    if not all(evidence.get(key) is True for key in ("host", "lan", "internet", "synthetic_http")):
        raise VMError("Verifica isolamento/simulazione guest non riuscita: " + json.dumps(evidence))
    return evidence


def provision(base_dir: Path, guest_dir: Path, tool_dir: Path, install_frida=True, timeout=900) -> dict:
    base_dir = base_dir.resolve()
    if (base_dir / "metadata.json").exists():
        previous = json.loads((base_dir / "metadata.json").read_text(encoding="utf-8"))
        if previous.get("ready"):
            return {"status": "already_ready", "base_dir": str(base_dir)}
    stage = _stage(base_dir)
    if not (stage / "metadata.json").is_file():
        raise VMError("Prima eseguire la fase extract")
    original = json.loads((stage / "metadata.json").read_text(encoding="utf-8"))
    _validate_guest(guest_dir)
    runs = base_dir.parent / "bootstrap-runs"
    _private_dir(runs)
    run_dir = runs / uuid.uuid4().hex
    vm = AnalysisVM(run_dir, stage, {"id": "provisioning", "interaction": False, "trace": False, "_provisioning": True})
    try:
        vm.start()
        if not vm.wait_agent(timeout=timeout):
            raise VMError("Guest agent non disponibile durante il provisionamento")
        offline_frida = _upload_guest(vm, guest_dir.resolve(), tool_dir.resolve(), install_frida)
        script = "$ErrorActionPreference='Stop'; & 'C:\\Sandbox\\tools\\setup.ps1' -ToolDir 'C:\\Sandbox\\tools'"
        if offline_frida:
            script += " -InstallFrida"
        # setup must finish synchronously and persist sensor status, not just print successful start.
        rc, out, err = vm.exec(script, timeout=600)
        _json_write(run_dir / "setup-output.json", {"rc": rc, "stdout": out, "stderr": err, "offline_frida": offline_frida})
        if rc:
            for name in ("sensors.json", "sysmon-schema.txt", "sysmon-install.txt"):
                with contextlib.suppress(Exception):
                    vm.pull("C:\\Sandbox\\tools\\" + name, run_dir / name, max_bytes=4 * 1024 * 1024)
            try:
                diagnostic = json.loads(out.strip().lstrip("\ufeff"))
                detail = json.dumps({name: diagnostic.get(name) for name in ("sysmon", "procmon", "frida")})
            except (ValueError, AttributeError):
                detail = (err or out)[-2048:]
            raise VMError("Provisionamento collector fallito: " + detail[:3000])
        provision_json = run_dir / "provision.json"
        vm.pull("C:\\Sandbox\\provision.json", provision_json, max_bytes=1024 * 1024)
        guest_state = json.loads(provision_json.read_text(encoding="utf-8-sig"))
        if guest_state.get("ready") is not True or not isinstance(guest_state.get("capabilities"), dict):
            raise VMError("Collector non confermati pronti dal guest; base non pubblicata")
        if not validate_privacy_proof(guest_state.get("privacy")):
            raise VMError("Privacy guest non confermata dopo il setup; base non pubblicata")
        network = _verify_network(vm)
        _json_write(run_dir / "guest-network-proof.json", network)
        if not vm.shutdown(timeout=180):
            raise VMError("Arresto guest non pulito; immagine non pubblicata")
        _private_dir(base_dir)
        if any((base_dir / name).exists() for name in ("clean.qcow2", *SIDECARS)):
            raise VMError("File base già presenti senza stato pronto; nessuna sovrascrittura automatica")
        flattened = base_dir / f".clean-{vm.uuid}.qcow2"
        _run(["qemu-img", "convert", "-O", "qcow2", str(vm.overlay), str(flattened)])
        flattened.chmod(0o600)
        info = json.loads(_run(["qemu-img", "info", "--output=json", str(flattened)], timeout=30))
        if info.get("backing-filename"):
            raise VMError("L'immagine finale conserva un backing file; pubblicazione rifiutata")
        final_sidecars = {}
        for name, src in (("OVMF_VARS.fd", vm.private / "OVMF_VARS.fd"),
                          ("tpm2-00.permall", vm.private / "tpm/tpm2-00.permall")):
            temp = base_dir / ("." + name + "-" + vm.uuid)
            shutil.copyfile(src, temp)
            temp.chmod(0o600)
            final_sidecars[name] = temp
        # Metadata is the readiness commit marker, published only after image and sidecars.
        os.replace(flattened, base_dir / "clean.qcow2")
        for name, temp in final_sidecars.items():
            os.replace(temp, base_dir / name)
        profiles = [{**item, "os": "Windows 11", "clone_of": "same_clean_windows_base",
                     "available": True, "capabilities": guest_state["capabilities"]} for item in PROFILES]
        metadata = {**original, "ready": True, "phase": "provisioned", "provisioned_at": time.time(),
                    "capabilities": guest_state["capabilities"], "profiles": profiles,
                    "privacy": guest_state["privacy"],
                    "isolation": vm.isolation, "guest_network_proof": network,
                    "resources": {"memory_mb": 4096, "cores": 2, "concurrent_runs": 1},
                    "warnings": guest_state.get("warnings", []), "bootstrap_run": str(run_dir)}
        if install_frida and not offline_frida:
            metadata["warnings"].append("Frida offline non disponibile: profilo API/stack senza tracing fino a provisionamento dedicato")
        _json_write(base_dir / "profiles.json", profiles)
        _json_write(base_dir / "metadata.json", metadata)
        return {"status": "ready", "base_dir": str(base_dir), "profiles": profiles,
                "capabilities": guest_state["capabilities"], "warnings": metadata["warnings"], "bootstrap_run": str(run_dir)}
    finally:
        # For failed provision retain logs/evidence, never promote a dirty/partially prepared clone.
        vm.cleanup()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bootstrap locale isolato; non modifica la VM sorgente")
    parser.add_argument("phase", choices=("extract", "provision", "all", "status"))
    parser.add_argument("--source", type=Path)
    parser.add_argument("--base-dir", type=Path, default=DEFAULT_BASE)
    parser.add_argument("--snapshots-dir", type=Path)
    parser.add_argument("--snapshot", default="clean-base")
    parser.add_argument("--guest-dir", type=Path, default=ROOT / "guest")
    parser.add_argument("--tools-dir", type=Path, default=ROOT / "data/tools")
    parser.add_argument("--no-frida", action="store_true")
    parser.add_argument("--agent-timeout", type=int, default=900)
    args = parser.parse_args(argv)
    if args.phase in ("extract", "all") and (args.source is None or args.snapshots_dir is None):
        parser.error("extract/all require explicit --source and --snapshots-dir")
    os.umask(0o077)
    try:
        if args.phase == "status":
            from .vm import capabilities
            result = capabilities(args.base_dir)
        else:
            with bootstrap_lock(args.base_dir.resolve()):
                result = {}
                if args.phase in ("extract", "all"):
                    result = extract(args.source, args.base_dir, args.snapshot, args.snapshots_dir)
                if args.phase in ("provision", "all"):
                    result = provision(args.base_dir, args.guest_dir, args.tools_dir,
                                       install_frida=not args.no_frida, timeout=args.agent_timeout)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except (VMError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False), file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

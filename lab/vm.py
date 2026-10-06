"""Private disposable Windows clone; offline or public-only isolated IPv4 egress."""
from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import random
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import uuid

from .namespace import bwrap_command, tpm_bwrap_command
from .egress import EgressError, EgressGateway, validate_network_proof
from .privacy import validate_privacy_proof

MAX_FILE_BYTES = 100 * 1024 * 1024
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
RPC_MAX_BYTES = 2 * 1024 * 1024
CHUNK_BYTES = 48 * 1024
MAX_SCRIPT_BYTES = 64 * 1024


class VMError(RuntimeError):
    pass


class IsolationError(VMError):
    pass

class PrivacyError(VMError):
    pass


def _private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink() or path.stat().st_uid != os.getuid():
        raise VMError("Directory privata non affidabile")
    path.chmod(0o700)


def _json_write(path: Path, data: dict | list) -> None:
    tmp = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def _vnc_binary() -> str | None:
    candidates = [str(Path(sys.executable).parent / "vncdo"), shutil.which("vncdo")]
    return next((item for item in candidates if item and os.access(item, os.X_OK)), None)


def capabilities(base_dir: Path) -> dict:
    """Readiness is honest: existence does not assert a working namespace or sensor."""
    base_dir = Path(base_dir).resolve()
    try:
        metadata = json.loads((base_dir / "metadata.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        metadata = {}
    required = ("clean.qcow2", "OVMF_VARS.fd", "tpm2-00.permall")
    files_ok = all((base_dir / name).is_file() for name in required)
    tools = {name: bool(shutil.which(name)) for name in ("qemu-system-x86_64", "qemu-img", "swtpm", "bwrap", "ip")}
    tools["kvm"] = os.access("/dev/kvm", os.R_OK | os.W_OK)
    tools["vncdotool"] = _vnc_binary() is not None
    prerequisites = all(value for key, value in tools.items() if key != "vncdotool")
    return {"available": bool(metadata.get("ready") and files_ok and prerequisites),
            "status": "available" if metadata.get("ready") and files_ok and prerequisites else "unavailable",
            "detail": "Base provisionata; isolamento verificato ad ogni avvio" if metadata.get("ready") else "Base pulita non ancora provisionata",
            "base_ready": bool(metadata.get("ready") and files_ok), "tools": tools,
            "network": {"default": "offline", "supported": ["offline", "internet"],
                        "internet_prerequisites": {name: bool(shutil.which("/usr/sbin/nft" if name == "nft" else name)) for name in ("slirp4netns", "nft")},
                        "internet_confirmed": False, "confirmation": "runtime nft/namespace/gateway/TLS-identity proof required"},
            "guest": metadata.get("capabilities", {}), "profiles": metadata.get("profiles", []),
            "privacy": metadata.get("privacy", {"status": "unverified", "verified": False}),
            "resources": {"memory_mb": 4096, "cores": 2, "concurrent_runs": 1},
            "isolation": {"required": True, "confirmed": False, "mechanism": "bubblewrap user/net/mount/pid namespaces + slirp restrict=on",
                          "guest_internet": False, "guest_lan": False, "guest_host": False,
                          "synthetic_http": "10.0.2.100:80", "dns": "unavailable",
                          "shared_folders": False, "spice": False, "usb_passthrough": False},
            "warnings": [] if metadata.get("ready") else ["Analisi dinamica indisponibile fino al bootstrap isolato"]}


class AnalysisVM:
    def __init__(self, run_dir: Path, base_dir: Path, profile: dict):
        self.run_dir = Path(run_dir).absolute()
        self.base_dir = Path(base_dir).resolve()
        self.profile = dict(profile)
        self.uuid = uuid.uuid4().hex
        self.private = self.run_dir / "v"
        self.overlay = self.private / f"overlay-{self.uuid}.qcow2"
        self.agent_socket = self.private / "a"
        self.vnc_socket = self.private / "v"
        self.tpm_socket = self.private / "t"
        self.qmp_socket = self.private / "q"
        self.proc: subprocess.Popen | None = None
        self.tpm_proc: subprocess.Popen | None = None
        self.egress: EgressGateway | None = None
        self._lock = None
        self._streams = []
        self._rpc_lock = threading.Lock()
        self._started = False
        self._closed = False
        self._isolation_confirmed = False
        self.isolation = {"confirmed": False, "required": True, "guest_internet": False,
                          "guest_lan": False, "guest_host": False}
        self.capabilities = capabilities(self.base_dir)
        self.warnings: list[str] = []
        self.clean_shutdown = False
        self.privacy: dict = {"status": "unverified", "verified": False}
        self._privacy_confirmed = False

    @property
    def network_mode(self) -> str:
        # Maintenance/provisioning never inherit an Internet analysis profile.
        if any(self.profile.get(key) for key in ("_provisioning", "_maintenance", "_maintenance_media")):
            return "offline"
        mode = self.profile.get("network", "offline")
        if mode not in ("offline", "internet"):
            raise VMError("Modalità rete sconosciuta; nessun fallback permissivo")
        return mode

    def _lock_runtime(self):
        _private_dir(self.base_dir.parent)
        path = self.base_dir.parent / ".runtime.lock"
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        self._lock = os.fdopen(fd, "a+")
        try:
            fcntl.flock(self._lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            self._lock.close()
            self._lock = None
            raise VMError("Un'altra analisi o provisionamento è in corso; esecuzioni sequenziali obbligatorie") from exc

    def _check_paths(self):
        if self.run_dir.is_symlink() or self.run_dir.resolve() != self.run_dir:
            raise VMError("Directory della sessione deve essere canonica e senza link simbolici")
        if self.base_dir == self.run_dir or self.base_dir.is_relative_to(self.run_dir) or self.run_dir.is_relative_to(self.base_dir):
            raise VMError("Directory base e sessione devono essere separate")
        for path in (self.run_dir, self.base_dir, self.private):
            if any(char in str(path) for char in (",", "\n", "\r", ":")):
                raise VMError("Percorso non compatibile con QEMU")
        if any(len(os.fsencode(path)) >= 104 for path in (self.agent_socket, self.vnc_socket, self.tpm_socket, self.qmp_socket)):
            raise VMError("Percorso della sessione troppo lungo per socket Unix; usare una directory più corta")
        for name in ("clean.qcow2", "OVMF_VARS.fd", "tpm2-00.permall"):
            path = self.base_dir / name
            if not path.is_file() or path.is_symlink():
                raise VMError(f"File base mancante/non affidabile: {name}")
        if not self.profile.get("_provisioning") and not self.capabilities["base_ready"]:
            raise VMError("Base non provisionata: bootstrap necessario")
        for command in ("qemu-img", "qemu-system-x86_64", "swtpm", "bwrap", "ip"):
            if not shutil.which(command):
                raise VMError(f"Prerequisito mancante: {command}")
        if not os.access("/dev/kvm", os.R_OK | os.W_OK):
            raise VMError("KVM non disponibile; nessun fallback non verificato")
        if self.network_mode == "internet":
            for command in ("slirp4netns", "/usr/sbin/nft"):
                if not shutil.which(command):
                    raise VMError(f"Prerequisito Internet mancante: {command}")
            if not Path("/etc/ssl/certs/ca-certificates.crt").is_file():
                raise VMError("CA per verifica identità pubblica non disponibili")

    def _launch(self, command: list[str], log_name: str, *, pass_fds=()) -> subprocess.Popen:
        stream = open(self.run_dir / log_name, "ab", buffering=0)
        os.chmod(self.run_dir / log_name, 0o600)
        self._streams.append(stream)
        return subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stream, stderr=stream,
                                start_new_session=True, close_fds=True, pass_fds=pass_fds)

    def qemu_command(self) -> list[str]:
        """Hardware mirrors the source VM, excluding its sharing/forwarding devices."""
        restriction = "off" if self.network_mode == "internet" else "on"
        command = [
            "/usr/bin/qemu-system-x86_64", "-name", f"sandbox-{self.uuid},process=sandbox-{self.uuid}",
            "-uuid", str(uuid.UUID(self.uuid)), "-machine", "q35,hpet=off,smm=on,vmport=off,accel=kvm",
            "-global", "kvm-pit.lost_tick_policy=discard", "-global", "ICH9-LPC.disable_s3=1",
            "-cpu", "host,+hypervisor,+invtsc,l3-cache=on,migratable=no,hv_passthrough,topoext",
            "-smp", "cores=2,threads=1,sockets=1", "-m", "4096", "-device", "virtio-balloon",
            "-rtc", "base=localtime,clock=host,driftfix=slew", "-vga", "none",
            "-device", "qxl-vga,xres=1280,yres=800,ram_size=65536,vram_size=65536,vgamem_mb=64",
            "-display", "none", "-vnc", f"unix:{self.vnc_socket}", "-device", "virtio-serial-pci",
            "-chardev", f"socket,id=agent0,path={self.agent_socket},server=on,wait=off",
            "-device", "virtserialport,chardev=agent0,name=org.qemu.guest_agent.0",
            "-device", "virtio-rng-pci,rng=rng0", "-object", "rng-random,id=rng0,filename=/dev/urandom",
            "-device", "usb-ehci,id=input", "-device", "usb-kbd,bus=input.0", "-k", "en-us",
            "-device", "usb-tablet,bus=input.0", "-device", "virtio-net,netdev=nic",
            "-netdev", f"user,id=nic,hostname=sandbox,restrict={restriction},ipv6=off,guestfwd=tcp:10.0.2.100:80-cmd:/usr/bin/python3 -I /runner.py --http-stdio " + shlex.quote(str(self.run_dir / "http.jsonl")),
            "-object", f"filter-dump,id=cap0,netdev=nic,file={self.run_dir / 'network.pcap'},maxlen=65535",
            "-global", "driver=cfi.pflash01,property=secure,value=on",
            "-drive", "if=pflash,format=raw,unit=0,file=/usr/share/OVMF/OVMF_CODE_4M.fd,readonly=on",
            "-drive", f"if=pflash,format=raw,unit=1,file={self.private / 'OVMF_VARS.fd'}",
            "-device", "virtio-blk-pci,drive=SystemDisk",
            "-drive", f"id=SystemDisk,if=none,format=qcow2,file={self.overlay}",
            "-chardev", f"socket,id=chrtpm,path={self.tpm_socket}",
            "-tpmdev", "emulator,id=tpm0,chardev=chrtpm", "-device", "tpm-tis,tpmdev=tpm0",
            "-qmp", f"unix:{self.qmp_socket},server=on,wait=off", "-serial", "none", "-monitor", "none",
        ]
        if self.profile.get("_maintenance_media"):
            media = self.run_dir / "maintenance.iso"
            if media.is_symlink() or not media.is_file() or not 1 <= media.stat().st_size <= MAX_ARTIFACT_BYTES:
                raise VMError("Media offline non valido; soltanto ISO locale della sessione, entro 512 MiB")
            command += ["-drive", f"if=ide,index=2,media=cdrom,format=raw,readonly=on,file={media}"]
        return command

    def start(self):
        if self._started or self._closed:
            raise VMError("Sessione già avviata o chiusa; creare una nuova AnalysisVM")
        self._check_paths()
        _private_dir(self.run_dir)
        self._lock_runtime()
        try:
            self.private.mkdir(mode=0o700, exist_ok=False)
            tpm_dir = self.private / "tpm"
            tpm_dir.mkdir(mode=0o700)
            for name, dst in (("OVMF_VARS.fd", self.private / "OVMF_VARS.fd"),
                              ("tpm2-00.permall", tpm_dir / "tpm2-00.permall")):
                shutil.copyfile(self.base_dir / name, dst)
                dst.chmod(0o600)
            subprocess.run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b",
                            str(self.base_dir / "clean.qcow2"), str(self.overlay)],
                           check=True, timeout=30, capture_output=True)
            self.overlay.chmod(0o600)
            tpm_command = [
                "/usr/bin/swtpm", "socket", "--tpm2", "--tpmstate", f"dir={tpm_dir},mode=0600",
                "--ctrl", f"type=unixio,path={self.tpm_socket},mode=0600",
                "--flags", "not-need-init,startup-clear"]
            self.tpm_proc = self._launch(tpm_bwrap_command(self.private, tpm_command), "tpm.log")
            deadline = time.monotonic() + 10
            while not self.tpm_socket.exists():
                if self.tpm_proc.poll() is not None or time.monotonic() >= deadline:
                    raise VMError("Avvio TPM privato fallito; vedere tpm.log")
                time.sleep(0.1)
            command = self.qemu_command()
            if self.network_mode == "internet":
                self.egress = EgressGateway(self.run_dir, self.uuid)
                self.proc = self.egress.start(lambda info: self._launch(
                    bwrap_command(self.run_dir, self.base_dir, self.uuid, command,
                                  policy_path=self.egress.policy_path, info_fd=info),
                    "qemu.log", pass_fds=(info,)))
            else:
                self.proc = self._launch(bwrap_command(self.run_dir, self.base_dir, self.uuid, command), "qemu.log")
            expected_hash = hashlib.sha256(json.dumps(command).encode()).hexdigest()
            deadline = time.monotonic() + 60
            proof_path = self.run_dir / "namespace.json"
            while time.monotonic() < deadline:
                if self.proc.poll() is not None:
                    raise IsolationError("QEMU/namespace terminato durante l'avvio; vedere qemu.log")
                if proof_path.exists():
                    proof = json.loads(proof_path.read_text(encoding="utf-8"))
                    if proof.get("nonce") != self.uuid:
                        raise IsolationError("Attestazione namespace non appartiene alla sessione")
                    if proof.get("error"):
                        raise IsolationError(proof["error"])
                    if self._validate_start_proof(proof, expected_hash):
                        self.isolation = proof
                        self._isolation_confirmed = True
                        self._started = True
                        self.capabilities["isolation"] = proof
                        self.capabilities["network"]["internet_confirmed"] = self.network_mode == "internet"
                        self.ensure_privacy()
                        _json_write(self.run_dir / "vm.json", {"uuid": self.uuid, "profile": self.profile.get("id"),
                                    "memory_mb": 4096, "cores": 2, "isolation": proof, "privacy": self.privacy})
                        return
                    raise IsolationError("Attestazione namespace incompleta")
                time.sleep(0.1)
            raise IsolationError("Timeout verifica namespace; campioni non trasferiti")
        except BaseException:
            self.stop()
            raise

    def _validate_start_proof(self, proof: dict, expected_hash: str) -> bool:
        status = proof.get("capability_status", {})
        try:
            common = (proof.get("nonce") == self.uuid and proof.get("confirmed") is True
                      and proof.get("qemu_started") is True
                      and proof.get("host_net_namespace") == os.readlink("/proc/self/ns/net")
                      and proof.get("host_user_namespace") == os.readlink("/proc/self/ns/user")
                      and isinstance(proof.get("net_namespace"), str)
                      and isinstance(proof.get("user_namespace"), str)
                      and proof.get("net_namespace") != proof.get("host_net_namespace")
                      and proof.get("user_namespace") != proof.get("host_user_namespace")
                      and proof.get("capabilities_dropped") is True and proof.get("no_new_privs") is True
                      and all(int(status[name], 16) == 0 for name in ("CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb"))
                      and status["NoNewPrivs"] == "1" and proof.get("qemu_argv_sha256") == expected_hash)
            if not common:
                return False
            if self.network_mode == "internet":
                if self.egress is None:
                    return False
                self.egress.assert_live()
                return validate_network_proof(proof, self.egress.policy, self.egress.namespaces)
            return (proof.get("network_mode") == "offline" and proof.get("interfaces") == ["lo"]
                    and proof.get("external_route_blocked") is True and proof.get("slirp_restrict") is True
                    and proof.get("guest_internet") is False and proof.get("guest_lan") is False
                    and proof.get("guest_host") is False)
        except (KeyError, ValueError, TypeError, EgressError):
            return False

    def _assert_isolated(self):
        if not self._isolation_confirmed or self.proc is None or self.proc.poll() is not None:
            raise IsolationError("VM isolata non attiva: operazione guest rifiutata")
        if self.tpm_proc is None or self.tpm_proc.poll() is not None:
            raise VMError("TPM privato terminato")
        if self.network_mode == "internet":
            try:
                if self.egress is None:
                    raise EgressError("Gateway assente")
                self.egress.assert_live()
            except EgressError as exc:
                self.stop()
                raise IsolationError(str(exc)) from exc

    @contextlib.contextmanager
    def _rpc_guard(self, deadline: float):
        if not self._rpc_lock.acquire(timeout=max(0, deadline - time.monotonic())):
            raise TimeoutError("Timeout attesa RPC guest")
        try:
            self._assert_isolated()
            yield
        finally:
            self._rpc_lock.release()

    def _agent(self, command: str, arguments: dict | None = None, timeout: float = 15):
        self._assert_isolated()
        deadline = time.monotonic() + max(0.05, min(float(timeout), 120))
        with self._rpc_guard(deadline), socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(max(0.01, deadline - time.monotonic()))
            sock.connect(str(self.agent_socket))
            pending = bytearray()
            consumed = 0

            def response(synchronizing=False):
                nonlocal consumed
                marker_seen = not synchronizing
                while True:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Timeout RPC guest")
                    if not marker_seen:
                        marker = pending.find(b"\xff")
                        if marker >= 0:
                            del pending[:marker + 1]
                            marker_seen = True
                        else:
                            pending.clear()
                    newline = pending.find(b"\n") if marker_seen else -1
                    if newline >= 0:
                        line = bytes(pending[:newline])
                        del pending[:newline + 1]
                        result = json.loads(line.lstrip(b"\xff"))
                        if not isinstance(result, dict):
                            raise VMError("Risposta guest non valida")
                        return result
                    sock.settimeout(max(0.01, deadline - time.monotonic()))
                    chunk = sock.recv(4096)
                    consumed += len(chunk)
                    if not chunk or consumed > RPC_MAX_BYTES:
                        raise VMError("Risposta guest troppo grande o connessione chiusa")
                    pending.extend(chunk)

            sync_id = int.from_bytes(os.urandom(4), "big")
            sync = {"execute": "guest-sync-delimited", "arguments": {"id": sync_id}}
            sock.sendall(b"\xff" + json.dumps(sync).encode() + b"\n")
            for _ in range(16):
                result = response(synchronizing=True)
                if result.get("return") == sync_id:
                    break
            else:
                raise VMError("Sincronizzazione guest fallita")
            request = {"execute": command}
            if arguments is not None:
                request["arguments"] = arguments
            payload = json.dumps(request).encode() + b"\n"
            if len(payload) > RPC_MAX_BYTES:
                raise VMError("Richiesta guest troppo grande")
            sock.settimeout(max(0.01, deadline - time.monotonic()))
            sock.sendall(payload)
            # QGA guest-shutdown sends no success response; poweroff is verified by process exit.
            if command == "guest-shutdown":
                return None
            result = response()
            if "error" in result:
                raise VMError("RPC guest: " + json.dumps(result["error"], ensure_ascii=False)[:2048])
            return result.get("return")

    def wait_agent(self, timeout=240) -> bool:
        timeout = max(1, min(float(timeout), 900))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self._assert_isolated()
            try:
                self._agent("guest-ping", timeout=min(5, deadline - time.monotonic()))
                return True
            except (OSError, ValueError, VMError, TimeoutError):
                time.sleep(min(2, max(0, deadline - time.monotonic())))
        return False

    def wait_desktop(self, timeout=180) -> bool:
        """QGA can answer before interactive logon; require the actual Quickemu shell."""
        deadline = time.monotonic() + max(1, min(float(timeout), 300))
        script = r"Write-Output (@(Get-Process -Name explorer -IncludeUserName -ErrorAction SilentlyContinue | Where-Object {$_.SessionId -gt 0 -and $_.UserName -match '\\Quickemu$'}).Count -gt 0)"
        while time.monotonic() < deadline:
            try:
                rc, out, _ = self.exec(script, timeout=max(1, deadline - time.monotonic()))
            except (OSError, ValueError, VMError, TimeoutError):
                return False
            if rc == 0 and out.strip().lower() == "true":
                return True
            time.sleep(min(2, max(0, deadline - time.monotonic())))
        return False

    def _validate_privacy_proof(self, proof: dict) -> bool:
        return validate_privacy_proof(proof, expected_nonce=self.uuid)

    def _assert_privacy(self):
        if not self._privacy_confirmed or not self._validate_privacy_proof(self.privacy):
            raise PrivacyError("Privacy guest non verificata: trasferimento rifiutato")

    def ensure_privacy(self) -> dict:
        """Apply before any sample transfer; also safe for offline base maintenance."""
        self._assert_isolated()
        if self._privacy_confirmed:
            self._assert_privacy()
            return json.loads(json.dumps(self.privacy))
        try:
            if not self.wait_agent(timeout=360):
                raise PrivacyError("Guest agent non pronto: privacy non verificata")
            if not self.wait_desktop(timeout=180):
                raise PrivacyError("Desktop Quickemu non pronto: privacy non verificata")
            script = Path(__file__).resolve().parent.parent / "guest" / "privacy.ps1"
            if (script.is_symlink() or script.resolve() != script or not script.is_file()
                    or not 1 <= script.stat().st_size <= MAX_SCRIPT_BYTES):
                raise PrivacyError("Script privacy fidato assente/non valido/oltre limite")
            digest = hashlib.sha256(script.read_bytes()).hexdigest()
            rc, out, err = self.exec(
                r"$ErrorActionPreference='Stop'; New-Item -ItemType Directory -Force 'C:\Sandbox\tools' | Out-Null",
                timeout=60)
            if rc:
                raise PrivacyError("Preparazione privacy fallita: " + (err or out)[:1024])
            # This is the only pre-privacy upload; source and destination are pinned above.
            self._push_file(script, r"C:\Sandbox\tools\privacy.ps1")
            command = (
                r"$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; try { if ((Get-FileHash -LiteralPath "
                r"'C:\Sandbox\tools\privacy.ps1' -Algorithm SHA256).Hash.ToLowerInvariant() -ne '"
                + digest + r"') { throw 'Script privacy hash non valido' }; & "
                r"'C:\Sandbox\tools\privacy.ps1' -Mode apply -Nonce '" + self.uuid
                + r"' } catch { [Console]::Error.WriteLine(($_ | Out-String) + $_.ScriptStackTrace); exit 1 }")
            rc, out, err = self.exec(command, timeout=300)
            if rc or "Output troncato" in err:
                raise PrivacyError("Enforcement privacy rifiutato: " + (err or out)[-4096:])
            # Script emits compact JSON last; cmdlet informational banners are not a proof.
            lines = [line.strip() for line in out.lstrip("\ufeff").splitlines() if line.strip()]
            proof = json.loads(lines[-1]) if lines else None
            if not self._validate_privacy_proof(proof):
                raise PrivacyError("Readback privacy guest incompleto/non conforme")
            proof["script_sha256"] = digest
            _json_write(self.run_dir / "privacy.json", proof)
            self.privacy = proof
            self._privacy_confirmed = True
            self.capabilities["privacy"] = proof
            return json.loads(json.dumps(proof))
        except BaseException:
            self.privacy = {"status": "failed", "verified": False, "nonce": self.uuid}
            self._privacy_confirmed = False
            self.stop()
            raise

    def exec(self, ps: str, timeout=120) -> tuple[int, str, str]:
        self._assert_isolated()
        if not isinstance(ps, str) or len(ps.encode("utf-8")) > MAX_SCRIPT_BYTES:
            raise VMError("Script PowerShell oltre il limite")
        timeout = max(1, min(float(timeout), 600))
        deadline = time.monotonic() + timeout
        encoded = base64.b64encode(ps.encode("utf-16le")).decode("ascii")
        stage = "avvio RPC guest-exec"
        try:
            launched = self._agent("guest-exec", {"path": "powershell.exe", "arg": ["-NoProfile", "-NonInteractive",
                                   "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded], "capture-output": True},
                                   timeout=min(120, timeout))
            if not isinstance(launched, dict) or not isinstance(launched.get("pid"), int):
                raise VMError("PID guest non valido")
            while time.monotonic() < deadline:
                stage = "stato RPC guest-exec-status"
                status = self._agent("guest-exec-status", {"pid": launched["pid"]}, timeout=min(120, deadline - time.monotonic()))
                if not isinstance(status, dict):
                    raise VMError("Stato esecuzione guest non valido")
                if status.get("exited"):
                    def decode(key):
                        text = status.get(key, "")
                        if not isinstance(text, str) or len(text) > RPC_MAX_BYTES:
                            raise VMError("Output guest oltre il limite")
                        return base64.b64decode(text, validate=True).decode("utf-8", "replace")
                    rc = status.get("exitcode", 1)
                    if not isinstance(rc, int):
                        raise VMError("Exit code guest non valido")
                    out, err = decode("out-data"), decode("err-data")
                    if status.get("out-truncated") or status.get("err-truncated"):
                        self.warnings.append("Output PowerShell troncato dal guest agent")
                        err += "\n[Output troncato dal guest agent]"
                    return rc, out, err
                time.sleep(min(0.5, max(0, deadline - time.monotonic())))
            stage = "deadline complessiva"
            raise TimeoutError("Timeout PowerShell: VM terminata per sicurezza")
        except (OSError, TimeoutError, ValueError, VMError) as exc:
            # RPC failure or timeout cannot leave an uncontrolled launcher alive.
            self.stop()
            if isinstance(exc, TimeoutError):
                raise TimeoutError(f"Timeout PowerShell ({stage}); VM terminata per sicurezza") from exc
            raise

    @staticmethod
    def _guest_path(path: str):
        if not isinstance(path, str) or not path or len(path) > 1024 or "\x00" in path:
            raise VMError("Percorso guest non valido")
        if path.startswith(("\\\\", "//")) or len(path) < 3 or path[1:3] != ":\\":
            raise VMError("Solo percorsi locali assoluti del guest")

    def push(self, src: Path, dst: str):
        self._assert_isolated()
        self._assert_privacy()
        self._push_file(src, dst)

    def _push_file(self, src: Path, dst: str):
        """Private transfer primitive; public push always requires effective privacy."""
        self._assert_isolated()
        self._guest_path(dst)
        src = Path(src)
        if not src.is_file() or src.is_symlink() or src.stat().st_size > MAX_FILE_BYTES:
            raise VMError("File da trasferire non valido o oltre 100 MiB")
        deadline = time.monotonic() + 300
        handle = self._agent("guest-file-open", {"path": dst, "mode": "wb"}, timeout=60)
        total = 0
        try:
            with open(src, "rb") as stream:
                while chunk := stream.read(CHUNK_BYTES):
                    total += len(chunk)
                    if total > MAX_FILE_BYTES or time.monotonic() >= deadline:
                        raise VMError("Trasferimento guest oltre i limiti")
                    result = self._agent("guest-file-write", {"handle": handle,
                                         "buf-b64": base64.b64encode(chunk).decode("ascii")},
                                         timeout=min(60, deadline - time.monotonic()))
                    if not isinstance(result, dict) or result.get("count") != len(chunk):
                        raise VMError("Scrittura guest parziale")
        finally:
            with contextlib.suppress(Exception):
                self._agent("guest-file-close", {"handle": handle}, timeout=30)

    def _local_destination(self, path: Path) -> Path:
        path = Path(path).absolute()
        if path.is_symlink() or not path.resolve().is_relative_to(self.run_dir.resolve()):
            raise VMError("Destinazione artefatto fuori dalla sessione")
        _private_dir(path.parent)
        return path

    def pull(self, src: str, dst: Path, max_bytes=MAX_FILE_BYTES):
        self._assert_isolated()
        self._guest_path(src)
        max_bytes = max(1, min(int(max_bytes), MAX_ARTIFACT_BYTES))
        dst = self._local_destination(dst)
        part = dst.with_name(dst.name + ".part-" + self.uuid)
        deadline = time.monotonic() + 300
        handle = self._agent("guest-file-open", {"path": src, "mode": "rb"}, timeout=60)
        total = 0
        try:
            with open(part, "xb") as stream:
                os.chmod(part, 0o600)
                while True:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Timeout acquisizione artefatto")
                    result = self._agent("guest-file-read", {"handle": handle, "count": min(CHUNK_BYTES, max_bytes - total + 1)},
                                         timeout=min(60, deadline - time.monotonic()))
                    if not isinstance(result, dict) or not isinstance(result.get("buf-b64", ""), str):
                        raise VMError("File guest non valido")
                    chunk = base64.b64decode(result.get("buf-b64", ""), validate=True)
                    total += len(chunk)
                    if len(chunk) > CHUNK_BYTES or total > max_bytes or result.get("count") != len(chunk):
                        raise VMError("Artefatto guest oltre il limite o conteggio non valido")
                    stream.write(chunk)
                    if result.get("eof") is True:
                        break
                    if not chunk:
                        raise VMError("Trasferimento guest fermo senza EOF")
            os.replace(part, dst)
        finally:
            with contextlib.suppress(Exception):
                self._agent("guest-file-close", {"handle": handle}, timeout=30)
            with contextlib.suppress(FileNotFoundError):
                part.unlink()

    def _vnc(self, args: list[str], timeout=20):
        self._assert_isolated()
        executable = _vnc_binary()
        if executable is None:
            raise VMError("vncdotool non disponibile; screenshot/interazione non eseguiti")
        # vncdotool discovers AF_UNIX from an existing bare socket pathname (not unix:PATH).
        proc = subprocess.Popen([executable, "-s", str(self.vnc_socket), *args], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            out, err = proc.communicate(timeout=timeout)
            if proc.returncode:
                raise VMError("VNC: " + err.decode("utf-8", "replace")[:2048])
        finally:
            self._kill_group(proc)

    def screenshot(self, path: Path):
        path = self._local_destination(path)
        self._vnc(["capture", str(path)])
        if not path.is_file() or path.stat().st_size > 32 * 1024 * 1024:
            raise VMError("Screenshot assente o oltre il limite")
        path.chmod(0o600)

    def interact(self, seed: int):
        self._assert_isolated()
        if not self.profile.get("interaction"):
            return []
        rng = random.Random(int(seed))
        events = []
        try:
            for index in range(6):
                x, y = rng.randint(1030, 1140), rng.randint(260, 360)
                args = ["move", str(x), str(y)]
                action = "move"
                if index in (2, 5):
                    args += ["click", "1"]
                    action = "left_click"
                self._vnc(args, timeout=10)
                events.append({"time": time.time(), "action": action, "x": x, "y": y,
                               "intent": "regione desktop destra, nessun testo o tasto", "completed": True})
                _json_write(self.run_dir / "interaction.json", {"seed": int(seed), "events": events,
                            "warning": "La regione è scelta per evitare icone/taskbar; il contenuto del guest può cambiare"})
                time.sleep(0.3)
        except Exception as exc:
            events.append({"time": time.time(), "action": "error", "detail": str(exc)[:1024]})
            _json_write(self.run_dir / "interaction.json", {"seed": int(seed), "events": events})
            raise
        return events

    @staticmethod
    def _kill_group(proc: subprocess.Popen | None):
        if proc is None:
            return
        # Kill the group even after its leader exited: helper descendants must not survive.
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(proc.pid, signal.SIGKILL)
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=5)
        finally:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(proc.pid, signal.SIGKILL)

    def shutdown(self, timeout=120) -> bool:
        """Bootstrap-only graceful poweroff; clean image is never saved after forced kill."""
        self._assert_isolated()
        try:
            self._agent("guest-shutdown", {"mode": "powerdown"}, timeout=10)
        except Exception:
            self.clean_shutdown = False
            self.stop()
            return False
        try:
            self.proc.wait(timeout=max(1, min(float(timeout), 240)))
            self.clean_shutdown = self.proc.returncode == 0
        except subprocess.TimeoutExpired:
            self.clean_shutdown = False
        finally:
            self.stop()
        return self.clean_shutdown

    def stop(self):
        self._isolation_confirmed = False
        self._privacy_confirmed = False
        self.isolation["active"] = False
        try:
            self._kill_group(self.proc)
        finally:
            try:
                if self.egress is not None:
                    self.egress.close()
            finally:
                try:
                    self._kill_group(self.tpm_proc)
                finally:
                    self.proc = None
                    self.tpm_proc = None
                    for stream in self._streams:
                        with contextlib.suppress(Exception):
                            stream.close()
                    self._streams.clear()
                    if self._lock is not None:
                        with contextlib.suppress(Exception):
                            fcntl.flock(self._lock.fileno(), fcntl.LOCK_UN)
                        self._lock.close()
                        self._lock = None
                    self._closed = True

    def cleanup(self):
        """Destroy disposable guest disk/keys, retaining forensic artifacts and evidence."""
        self.stop()
        if self.private.exists() and not self.private.is_symlink():
            shutil.rmtree(self.private)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.cleanup()

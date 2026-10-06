"""Fail-closed QEMU namespace launcher and bounded synthetic HTTP service.

This file is also executed as /runner.py inside bubblewrap; imports are stdlib only.
"""
from __future__ import annotations

import ctypes
import errno
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import select
import time

HTTP_PORT = 18080
HTTP_BODY = b"Sandbox locale: servizio HTTP simulato, nessun accesso esterno.\n"
MAX_HTTP_REQUEST = 8192
MAX_HTTP_CONNECTIONS = 8
MAX_HTTP_LOG = 4 * 1024 * 1024


def bwrap_command(run_dir: Path, base_dir: Path, nonce: str, qemu: list[str] | None = None,
                  *, policy_path: Path | None = None, info_fd: int | None = None) -> list[str]:
    """Build only the permitted mounts; never fall back to host networking."""
    runner = Path(__file__).resolve()
    command = [
        "/usr/bin/bwrap", "--unshare-all", "--die-with-parent",
        "--uid", "0", "--gid", "0", "--cap-drop", "ALL",
        "--cap-add", "CAP_NET_ADMIN", "--cap-add", "CAP_SETPCAP", "--clearenv",
        "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "HOME", "/tmp",
        "--setenv", "LANG", "C.UTF-8", "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/bin", "/bin", "--symlink", "usr/sbin", "/sbin",
        "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
        "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
        "--dir", "/etc", "--dir", "/run",
    ]
    for path in ("/etc/ld.so.cache", "/etc/localtime"):
        if Path(path).is_file():
            command += ["--ro-bind", path, path]
    if info_fd is not None:
        command += ["--info-fd", str(info_fd)]
    network_mounts = []
    if policy_path is not None:
        from . import egress
        policy_path = Path(policy_path).resolve()
        resolver = policy_path.with_name("egress-resolv.conf")
        network_mounts = ["--ro-bind", str(Path(egress.__file__).resolve()), "/egress.py",
                          "--ro-bind", str(policy_path), "/egress-policy.json",
                          "--ro-bind", str(policy_path), str(policy_path),
                          "--ro-bind", str(resolver), "/etc/resolv.conf",
                          "--ro-bind", str(resolver), str(resolver),
                          "--ro-bind", "/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/certs/ca-certificates.crt"]
    if qemu is not None:
        command += ["--dev-bind", "/dev/kvm", "/dev/kvm"]
    command += [
        "--bind", str(run_dir.resolve()), str(run_dir.resolve()),
        "--ro-bind", str(base_dir.resolve()), str(base_dir.resolve()),
        "--ro-bind", str(runner), "/runner.py",
    ]
    command += network_mounts
    command += [
        "--chdir", str(run_dir.resolve()),
        "/usr/bin/python3", "-I", "/runner.py", "--run-dir", str(run_dir.resolve()),
        "--nonce", nonce, "--host-net", os.readlink("/proc/self/ns/net"),
        "--host-user", os.readlink("/proc/self/ns/user"),
    ]
    if policy_path is not None:
        policy = egress.read_json(policy_path)
        egress.validate_policy(policy)
        if policy["nonce"] != nonce:
            raise RuntimeError("Policy non appartiene alla sessione")
        command += ["--internet-policy", "/egress-policy.json", "--policy-sha256", egress.digest(policy)]
    if qemu is None:
        command += ["--probe"]
    else:
        command += ["--", *qemu]
    return command


def tpm_bwrap_command(private_dir: Path, argv: list[str]) -> list[str]:
    """Constrain the second guest-facing parser, swtpm, to private run state."""
    command = [
        "/usr/bin/bwrap", "--unshare-all", "--die-with-parent", "--new-session",
        "--cap-drop", "ALL", "--clearenv", "--setenv", "PATH", "/usr/bin:/bin",
        "--setenv", "HOME", "/tmp", "--setenv", "LANG", "C.UTF-8",
        "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin",
        "--symlink", "usr/sbin", "/sbin", "--symlink", "usr/lib", "/lib",
        "--symlink", "usr/lib64", "/lib64", "--proc", "/proc",
        "--remount-ro", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/etc",
    ]
    for path in ("/etc/ld.so.cache", "/etc/localtime"):
        if Path(path).is_file():
            command += ["--ro-bind", path, path]
    command += ["--bind", str(private_dir.resolve()), str(private_dir.resolve()),
                "--remount-ro", "/", "--chdir", str(private_dir.resolve()), "--", *argv]
    return command


def _atomic_json(path: Path, value: dict) -> None:
    temp = path.with_name(path.name + ".tmp-" + os.urandom(8).hex())
    fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
    os.replace(temp, path)


def namespace_evidence(host_net: str, host_user: str) -> dict:
    """Verify the actual namespace, not merely successful process creation."""
    net = os.readlink("/proc/self/ns/net")
    user = os.readlink("/proc/self/ns/user")
    if net == host_net or user == host_user:
        raise RuntimeError("Namespace rete/utente non separati: avvio rifiutato")
    result = subprocess.run(["/usr/sbin/ip", "link", "set", "lo", "up"], timeout=5,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    if result.returncode:
        raise RuntimeError("Configurazione loopback fallita: " + result.stderr.decode("utf-8", "replace")[:2048])
    links = json.loads(subprocess.check_output(["/usr/sbin/ip", "-j", "link"], timeout=5))
    names = [item.get("ifname") for item in links]
    if names != ["lo"]:
        raise RuntimeError(f"Interfacce di rete inattese: {names!r}")
    routes = []
    for family in ("-4", "-6"):
        routes += json.loads(subprocess.check_output(
            ["/usr/sbin/ip", family, "-j", "route", "show", "table", "all"], timeout=5))
    if any(route.get("dev") not in (None, "lo") or route.get("dst") == "default" for route in routes):
        raise RuntimeError("Routing esterno presente: avvio rifiutato")
    # An active failure to route supplements the interface inspection. No packet can leave this netns.
    blocked = False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        try:
            sock.connect(("192.0.2.1", 9))
        except OSError:
            blocked = True
    if not blocked:
        raise RuntimeError("Il namespace dispone di accesso esterno")
    return {"confirmed": True, "net_namespace": net, "user_namespace": user,
            "host_net_namespace": host_net, "host_user_namespace": host_user,
            "interfaces": names, "routes": routes, "external_route_blocked": blocked,
            "filesystem": "bubblewrap: /usr RO, base RO, run privato RW, /dev sintetico",
            "network_mode": "offline", "guest_internet": False, "guest_lan": False, "guest_host": False,
            "slirp_restrict": True, "host_forwards": [], "shared_folders": False,
            "spice": False, "usb_passthrough": False}


def drop_capabilities() -> dict:
    """No namespace administration capability survives into the QEMU process."""
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), "no_new_privs non impostato")
    for cap in range(64):
        if libc.prctl(24, cap, 0, 0, 0) != 0:  # PR_CAPBSET_DROP
            error = ctypes.get_errno()
            if error != errno.EINVAL:  # kernels expose at most CAP_LAST_CAP
                raise OSError(error, "Impossibile rimuovere capability bounding set")

    class Header(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class Data(ctypes.Structure):
        _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32),
                    ("inheritable", ctypes.c_uint32)]

    header = Header(0x20080522, 0)
    data = (Data * 2)()
    if libc.capset(ctypes.byref(header), ctypes.byref(data)) != 0:
        raise OSError(ctypes.get_errno(), "Impossibile rimuovere capability")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    if any(int(status[name].strip(), 16) != 0 for name in ("CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb")):
        raise RuntimeError("Capability residue: avvio rifiutato")
    if status.get("NoNewPrivs", "").strip() != "1":
        raise RuntimeError("no_new_privs non verificato")
    return {"capabilities_dropped": True, "no_new_privs": True,
            "capability_status": {name: status[name].strip() for name in
                                  ("CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb", "NoNewPrivs")}}


def _egress_module():
    # -I excludes the script directory: explicitly load the immutable bind mount.
    import importlib.util
    spec = importlib.util.spec_from_file_location("sandbox_egress", "/egress.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def internet_evidence(args, baseline: dict) -> tuple[dict, dict]:
    egress = _egress_module()
    policy = egress.read_json(args.internet_policy)
    egress.validate_policy(policy)
    if policy["nonce"] != args.nonce or egress.digest(policy) != args.policy_sha256:
        raise RuntimeError("Nonce/hash policy Internet non corrispondenti")
    # No interface/route exists yet. Install and verify the packet filter before
    # even allowing the host controller to create a user-mode gateway.
    initial = egress.install_firewall(policy, args.host_net)
    _atomic_json(args.run_dir / "egress-request.json",
                 {"nonce": args.nonce, "base_policy_sha256": args.policy_sha256,
                  "net_namespace": baseline["net_namespace"], "user_namespace": baseline["user_namespace"],
                  "firewall": initial})
    deadline = time.monotonic() + 25
    ready_path = args.run_dir / "egress-ready.json"
    while not ready_path.exists():
        if time.monotonic() >= deadline:
            raise RuntimeError("Timeout gateway isolato; QEMU non avviato")
        time.sleep(0.05)
    gateway = egress.read_json(ready_path)
    if (gateway.get("nonce") != args.nonce or gateway.get("ready") is not True
            or gateway.get("base_policy_sha256") != args.policy_sha256
            or gateway.get("net_namespace") != baseline["net_namespace"]
            or gateway.get("user_namespace") != baseline["user_namespace"]
            or any(gateway.get(key) is not True for key in
                   ("sandbox", "seccomp", "disable_host_loopback", "disable_dns"))
            or gateway.get("cidr") != egress.OUTER_CIDR or gateway.get("interface") != egress.INTERFACE):
        raise RuntimeError("Gateway non appartiene a namespace/policy attesi")
    links = json.loads(subprocess.check_output(["/usr/sbin/ip", "-j", "link"], timeout=5))
    names = [item.get("ifname") for item in links]
    if names != ["lo", egress.INTERFACE] or any("UP" not in item.get("flags", []) for item in links):
        raise RuntimeError("Interfacce Internet non confermate")
    addresses = json.loads(subprocess.check_output(["/usr/sbin/ip", "-4", "-j", "addr"], timeout=5))
    observed = [(item.get("ifname"), addr.get("local"), addr.get("prefixlen"))
                for item in addresses for addr in item.get("addr_info", [])]
    if observed != [("lo", "127.0.0.1", 8), (egress.INTERFACE, egress.OUTER_ADDRESS, 24)]:
        raise RuntimeError("Indirizzi Internet inattesi")
    routes = json.loads(subprocess.check_output(
        ["/usr/sbin/ip", "-4", "-j", "route", "show", "table", "all"], timeout=5))
    defaults = [route for route in routes if route.get("dst") == "default"]
    if (len(defaults) != 1 or defaults[0].get("gateway") != egress.OUTER_GATEWAY
            or defaults[0].get("dev") != egress.INTERFACE):
        raise RuntimeError("Gateway/default route non confermati")
    allowed_dsts = {egress.OUTER_CIDR, egress.OUTER_ADDRESS, "10.77.0.0", "10.77.0.255"}
    for route in routes:
        if route.get("dst") == "default":
            continue
        if route.get("dev") == "lo":
            continue
        if route.get("dev") != egress.INTERFACE or route.get("dst") not in allowed_dsts or route.get("gateway"):
            raise RuntimeError("Route Internet inattesa")
    routes6 = json.loads(subprocess.check_output(
        ["/usr/sbin/ip", "-6", "-j", "route", "show", "table", "all"], timeout=5))
    if any(route.get("dst") == "default" or route.get("dev") not in (None, "lo", egress.INTERFACE) for route in routes6):
        raise RuntimeError("Route IPv6 esterna inattesa")
    lookup = json.loads(subprocess.check_output(
        ["/usr/sbin/ip", "-4", "-j", "route", "get", egress.RESOLVERS[0]], timeout=5))
    if (len(lookup) != 1 or lookup[0].get("dev") != egress.INTERFACE
            or lookup[0].get("gateway") != egress.OUTER_GATEWAY or lookup[0].get("prefsrc", lookup[0].get("src")) != egress.OUTER_ADDRESS):
        raise RuntimeError("Routing pubblico non confermato")
    egress.verify_ruleset(json.loads(subprocess.check_output(
        ["/usr/sbin/nft", "-j", "list", "ruleset"], timeout=5)), policy)
    # Two TLS-validated public echoes must agree. Unknown NAT/WAN identity fails
    # closed; the discovered reflection address is blocked before QEMU exists.
    final = egress.discover_public_identity(policy)
    firewall = egress.install_firewall(final, args.host_net, replace=True, previous_policy=policy)
    _atomic_json(args.run_dir / "egress-final-policy.json", final)
    result = dict(baseline)
    result.update({"network_mode": "internet", "guest_internet": True, "guest_lan": False, "guest_host": False,
                   "slirp_restrict": False, "external_route_blocked": False, "interfaces": names,
                   "routes": routes, "ipv6_routes": routes6, "gateway": gateway, "firewall": firewall,
                   "base_policy_sha256": args.policy_sha256, "policy_sha256": egress.digest(final),
                   "outer_address": egress.OUTER_ADDRESS, "outer_gateway": egress.OUTER_GATEWAY,
                   "resolvers": egress.RESOLVERS, "dns": "public upstream resolvers; no host/LAN DNS",
                   "public_identity": final["public_identity"], "public_identity_state": "confirmed-and-blocked",
                   "public_identity_limits": "One observed IPv4 egress identity; unknown alternate WAN identities/prefixes cannot be enumerated.",
                   "internet_verified": "two agreeing TLS-validated public IPv4 echoes before QEMU"})
    return result, final


def connectivity_probes(policy: dict) -> list[dict]:
    egress = _egress_module()
    results = []
    for target in policy["probe_targets"]:
        if egress.destination_allowed(target["address"], policy) != target["allowed"]:
            raise RuntimeError("Aspettativa sonda incompatibile con la policy")
        connected = False
        error = None
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            try:
                sock.connect((target["address"], target["port"]))
                connected = True
            except OSError as exc:
                error = str(exc)[:256]
        result = {**target, "connected": connected, "error": error, "passed": connected == target["allowed"]}
        results.append(result)
        if not result["passed"]:
            raise RuntimeError("Sonda rete fallita: " + json.dumps(result))
    return results


class SyntheticHTTP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = MAX_HTTP_CONNECTIONS

    def __init__(self, run_dir: Path):
        self.log_path = run_dir / "http.jsonl"
        self.log_lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(MAX_HTTP_CONNECTIONS)
        super().__init__(("127.0.0.1", HTTP_PORT), HTTPHandler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def record(self, request: bytes) -> None:
        # Do not persist executable bodies. Log only a bounded escaped request line.
        first = request.split(b"\r\n", 1)[0][:1024].decode("ascii", "backslashreplace")
        entry = {"time": time.time(), "request": first, "synthetic": True,
                 "endpoint": "10.0.2.100:80", "response_status": 200}
        with self.log_lock:
            if self.log_path.exists() and self.log_path.stat().st_size >= MAX_HTTP_LOG:
                return
            with open(self.log_path, "a", encoding="utf-8") as stream:
                os.chmod(self.log_path, 0o600)
                stream.write(json.dumps(entry, ensure_ascii=True) + "\n")


class HTTPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        request = bytearray()
        try:
            while len(request) < MAX_HTTP_REQUEST and b"\r\n\r\n" not in request:
                chunk = self.request.recv(min(1024, MAX_HTTP_REQUEST - len(request)))
                if not chunk:
                    break
                request.extend(chunk)
            self.server.record(bytes(request))
            # No URL lookup, DNS, file access, templates, subprocess or request evaluation.
            response = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n"
                        b"Connection: close\r\nCache-Control: no-store\r\nContent-Length: "
                        + str(len(HTTP_BODY)).encode("ascii") + b"\r\n\r\n" + HTTP_BODY)
            self.request.sendall(response)
        except (OSError, TimeoutError):
            pass


def http_stdio(log_path: Path) -> int:
    """A bounded responder per TCP connection, not a boot-time persistent socket."""
    request = bytearray()
    deadline = time.monotonic() + 8
    while len(request) < MAX_HTTP_REQUEST and b"\r\n\r\n" not in request:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([sys.stdin], [], [], remaining)[0]:
            return 1
        chunk = os.read(sys.stdin.fileno(), 1024)
        if not chunk:
            return 0
        request.extend(chunk)
    if b"\r\n\r\n" not in request:
        return 1
    first = request.split(b"\r\n", 1)[0][:1024].decode("ascii", "backslashreplace")
    try:
        if (log_path.name == "http.jsonl" and log_path.resolve().is_relative_to(Path.cwd().resolve())
                and not log_path.is_symlink() and (not log_path.exists() or log_path.stat().st_size < MAX_HTTP_LOG)):
            fd = os.open(log_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                os.write(fd, (json.dumps({"time": time.time(), "request": first, "synthetic": True,
                                         "endpoint": "10.0.2.100:80", "response_status": 200}) + "\n").encode())
            finally:
                os.close(fd)
    except OSError:
        pass
    response = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n"
                b"Connection: close\r\nCache-Control: no-store\r\nContent-Length: "
                + str(len(HTTP_BODY)).encode("ascii") + b"\r\n\r\n" + HTTP_BODY)
    sys.stdout.buffer.write(response)
    sys.stdout.buffer.flush()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--host-net", required=True)
    parser.add_argument("--host-user", required=True)
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--internet-policy", type=Path)
    parser.add_argument("--policy-sha256")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    os.umask(0o077)
    child = None
    server = None
    evidence = {"nonce": args.nonce, "confirmed": False, "qemu_started": False}
    try:
        evidence.update(namespace_evidence(args.host_net, args.host_user))
        policy = None
        if args.internet_policy is not None:
            evidence, policy = internet_evidence(args, evidence)
        elif args.policy_sha256:
            raise RuntimeError("Hash egress senza policy")
        evidence.update(drop_capabilities())
        if args.probe:
            if policy is not None:
                evidence["connectivity"] = connectivity_probes(policy)
            _atomic_json(args.run_dir / "namespace-probe.json", evidence)
            return 0
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        if not command or command[0] != "/usr/bin/qemu-system-x86_64":
            raise RuntimeError("Eseguibile QEMU non autorizzato")
        netdevs = [command[index + 1] for index, value in enumerate(command[:-1]) if value == "-netdev"]
        expected_restrict = "restrict=off" if policy is not None else "restrict=on"
        if (len(netdevs) != 1 or expected_restrict not in netdevs[0].split(",")
                or "ipv6=off" not in netdevs[0].split(",") or "hostfwd" in netdevs[0]):
            raise RuntimeError("Rete QEMU non corrisponde alla policy verificata")
        # Bound capture/file growth, descriptor use and total CPU consumption per process.
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
        resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024 ** 3, 8 * 1024 ** 3))
        resource.setrlimit(resource.RLIMIT_CPU, (1800, 1800))
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL)
        evidence.update({"qemu_started": True, "synthetic_http": "10.0.2.100:80",
                         "synthetic_bind": "per-connection stdio, inside isolated namespace",
                         "dns": evidence.get("dns", "unavailable: nessun servizio DNS esterno"),
                         "qemu_argv_sha256": hashlib.sha256(json.dumps(command).encode()).hexdigest()})
        _atomic_json(args.run_dir / "namespace.json", evidence)

        def terminate(signum, frame):
            if child is not None and child.poll() is None:
                child.terminate()
            raise SystemExit(128 + signum)

        signal.signal(signal.SIGTERM, terminate)
        signal.signal(signal.SIGINT, terminate)
        deadline = time.monotonic() + 2400
        while child.poll() is None:
            capture = args.run_dir / "network.pcap"
            if capture.exists() and capture.stat().st_size > 256 * 1024 * 1024:
                raise RuntimeError("Limite cattura PCAP (256 MiB) raggiunto; VM terminata")
            if time.monotonic() >= deadline:
                raise RuntimeError("Budget temporale VM (2400 secondi) raggiunto")
            time.sleep(0.5)
        return child.returncode
    except Exception as exc:
        evidence.update({"confirmed": False, "error": str(exc)[:2048]})
        _atomic_json(args.run_dir / ("namespace-probe.json" if args.probe else "namespace.json"), evidence)
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
        if server is not None:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--http-stdio":
        raise SystemExit(http_stdio(Path(sys.argv[2])))
    raise SystemExit(main())

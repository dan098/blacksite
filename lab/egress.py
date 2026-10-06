"""Public-only IPv4 egress. nft is invoked ONLY by the isolated runner.

The host controller only reads host addresses/routes and starts user-mode slirp;
it never changes host routes, interfaces, firewall or forwarding.
"""
from __future__ import annotations

import contextlib
import ctypes
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import resource
import select
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request

OUTER_CIDR = "10.77.0.0/24"
OUTER_GATEWAY = "10.77.0.2"
OUTER_ADDRESS = "10.77.0.100"
INTERFACE = "tap0"
RESOLVERS = ["1.1.1.1", "9.9.9.9"]
TABLE = "sandbox_egress"
MAX_JSON = 1024 * 1024
MAX_SECONDS = 2400
# Conservative superset of IANA special-use IPv4, including public exceptions.
DENIED_CIDRS = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
)
IDENTITY_URLS = ("https://api4.ipify.org", "https://checkip.amazonaws.com")


class EgressError(RuntimeError):
    pass


def digest(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _networks(values) -> list[str]:
    try:
        nets = [ipaddress.IPv4Network(item, strict=True) for item in values]
    except (ValueError, TypeError) as exc:
        raise EgressError("Prefissi IPv4 non validi") from exc
    return [str(net) for net in ipaddress.collapse_addresses(nets)]


def is_public_ipv4(address: str) -> bool:
    if not isinstance(address, str):
        return False
    try:
        ip = ipaddress.IPv4Address(address)
    except (ValueError, TypeError):
        return False
    return ip.is_global and not any(ip in ipaddress.IPv4Network(net) for net in DENIED_CIDRS)


def destination_allowed(address: str, policy: dict) -> bool:
    """Packet destination decision; DNS names/answers never grant exceptions."""
    validate_policy(policy)
    if not is_public_ipv4(address):
        return False
    ip = ipaddress.IPv4Address(address)
    return not any(ip in ipaddress.IPv4Network(net) for net in policy["blocked_ipv4"])


def policy_from_snapshot(addresses: list, routes4: list, routes6: list, nonce: str,
                         targets: list | None = None) -> dict:
    """Malformed/unknown host state is fatal, never an empty deny list."""
    if not isinstance(nonce, str) or not nonce or len(nonce) > 128:
        raise EgressError("Nonce egress non valido")
    if not isinstance(addresses, list) or not addresses or not isinstance(routes4, list) or not isinstance(routes6, list):
        raise EgressError("Snapshot rete host incompleto")
    blocked = list(DENIED_CIDRS)
    found4 = False
    for link in addresses:
        if not isinstance(link, dict) or not isinstance(link.get("ifname"), str) or not isinstance(link.get("addr_info"), list):
            raise EgressError("Indirizzi host non riconosciuti")
        for item in link["addr_info"]:
            if not isinstance(item, dict) or item.get("family") not in ("inet", "inet6"):
                raise EgressError("Famiglia indirizzo host sconosciuta")
            version = 4 if item["family"] == "inet" else 6
            try:
                if not isinstance(item["local"], str):
                    raise ValueError("nonliteral host address")
                address = ipaddress.ip_address(item["local"])
                prefix = item["prefixlen"]
                if address.version != version or type(prefix) is not int or not 0 <= prefix <= address.max_prefixlen:
                    raise ValueError("family/prefix")
                for key in ("peer", "broadcast"):
                    if key in item:
                        if not isinstance(item[key], str):
                            raise ValueError("nonliteral host address")
                        extra = ipaddress.ip_interface(item[key]).ip
                        if extra.version != version:
                            raise ValueError("family")
                        if version == 4:
                            blocked.append(str(extra) + "/32")
            except (KeyError, ValueError, TypeError) as exc:
                raise EgressError("Indirizzo host malformato") from exc
            if version == 4:
                found4 = True
                blocked.append(str(address) + "/32")
                # Block the complete directly-connected subnet, including public LANs.
                blocked.append(str(ipaddress.IPv4Network(f"{address}/{prefix}", strict=False)))
    default4 = False
    for version, routes in ((4, routes4), (6, routes6)):
        for route in routes:
            if not isinstance(route, dict) or not isinstance(route.get("dst"), str):
                raise EgressError("Route host non riconosciuta")
            try:
                dst = route["dst"]
                if dst == "default":
                    if not isinstance(route.get("dev"), str) or not route["dev"]:
                        raise ValueError("default senza interfaccia")
                    default4 |= version == 4
                else:
                    net = ipaddress.ip_network(dst, strict=False)
                    if net.version != version:
                        raise ValueError("family")
                    if version == 4:
                        # All nondefault routes are denied, not just RFC1918 LANs.
                        blocked.append(str(net))
                if "gateway" in route:
                    if not isinstance(route["gateway"], str):
                        raise ValueError("nonliteral gateway")
                    gateway = ipaddress.ip_address(route["gateway"])
                    if gateway.version != version:
                        raise ValueError("gateway family")
                    if version == 4:
                        blocked.append(str(gateway) + "/32")
            except (ValueError, TypeError) as exc:
                raise EgressError("Route host malformata") from exc
    if not found4 or not default4:
        raise EgressError("Identità/routing IPv4 host non verificabili")
    policy = {"version": 1, "nonce": nonce, "interface": INTERFACE, "outer_cidr": OUTER_CIDR,
              "resolvers": list(RESOLVERS), "blocked_ipv4": _networks(blocked),
              "host_snapshot_sha256": digest({"addresses": addresses, "routes4": routes4, "routes6": routes6}),
              "public_identity": None, "probe_targets": targets if targets is not None else []}
    validate_policy(policy)
    if any(not destination_allowed(ip, policy) for ip in RESOLVERS):
        raise EgressError("Resolver pubblico incluso nella rete host negata")
    return policy


def validate_policy(policy: dict) -> None:
    keys = {"version", "nonce", "interface", "outer_cidr", "resolvers", "blocked_ipv4",
            "host_snapshot_sha256", "public_identity", "probe_targets"}
    if not isinstance(policy, dict) or set(policy) != keys or type(policy["version"]) is not int or policy["version"] != 1:
        raise EgressError("Schema policy egress non valido")
    if (not isinstance(policy["nonce"], str) or not policy["nonce"] or len(policy["nonce"]) > 128
            or policy["interface"] != INTERFACE or policy["outer_cidr"] != OUTER_CIDR
            or policy["resolvers"] != RESOLVERS):
        raise EgressError("Configurazione egress non autorizzata")
    sha = policy["host_snapshot_sha256"]
    if not isinstance(sha, str) or len(sha) != 64 or any(ch not in "0123456789abcdef" for ch in sha):
        raise EgressError("Hash snapshot non valido")
    blocked = policy["blocked_ipv4"]
    if not isinstance(blocked, list) or not blocked or len(blocked) > 8192 or blocked != _networks(blocked):
        raise EgressError("Deny list egress non canonica")
    nets = [ipaddress.IPv4Network(net) for net in blocked]
    if any(not any(ipaddress.IPv4Network(base).subnet_of(net) for net in nets) for base in DENIED_CIDRS):
        raise EgressError("Intervalli privati/riservati non completamente negati")
    identity = policy["public_identity"]
    if identity is not None:
        if (not isinstance(identity, dict) or set(identity) != {"confirmed", "ipv4", "method", "sources"}
                or identity["confirmed"] is not True or not is_public_ipv4(identity["ipv4"])
                or identity["method"] != "agreeing_https_echo" or identity["sources"] != list(IDENTITY_URLS)
                or not any(ipaddress.IPv4Address(identity["ipv4"]) in net for net in nets)):
            raise EgressError("Identità pubblica host non confermata/negata")
    targets = policy["probe_targets"]
    if not isinstance(targets, list) or len(targets) > 32:
        raise EgressError("Sonde rete non valide")
    for target in targets:
        if (not isinstance(target, dict) or set(target) != {"address", "port", "allowed"}
                or type(target["port"]) is not int or not 1 <= target["port"] <= 65535
                or type(target["allowed"]) is not bool):
            raise EgressError("Sonda rete non valida")
        try:
            if not isinstance(target["address"], str):
                raise ValueError("nonliteral probe")
            ipaddress.IPv4Address(target["address"])
        except (ValueError, TypeError) as exc:
            raise EgressError("Sonda non IPv4") from exc


def with_public_identity(policy: dict, address: str) -> dict:
    validate_policy(policy)
    if not is_public_ipv4(address):
        raise EgressError("Echo HTTPS non ha restituito IPv4 pubblico")
    result = dict(policy)
    result["blocked_ipv4"] = _networks([*policy["blocked_ipv4"], address + "/32"])
    result["public_identity"] = {"confirmed": True, "ipv4": address,
                                 "method": "agreeing_https_echo", "sources": list(IDENTITY_URLS)}
    validate_policy(result)
    return result


def _host_json(argv: list[str]) -> list:
    result = subprocess.run(argv, check=True, capture_output=True, timeout=5)
    if len(result.stdout) > MAX_JSON:
        raise EgressError("Snapshot rete host troppo grande")
    value = json.loads(result.stdout)
    if not isinstance(value, list):
        raise EgressError("Snapshot rete host non riconosciuto")
    return value


def snapshot_policy(nonce: str, targets: list | None = None) -> dict:
    ip = shutil.which("/usr/sbin/ip")
    if not ip:
        raise EgressError("ip non disponibile")
    return policy_from_snapshot(_host_json([ip, "-j", "addr", "show"]),
                                _host_json([ip, "-4", "-j", "route", "show", "table", "all"]),
                                _host_json([ip, "-6", "-j", "route", "show", "table", "all"]), nonce, targets)


def _match(left, right):
    return {"match": {"op": "==", "left": left, "right": right}}


def ruleset_objects(policy: dict) -> list[dict]:
    validate_policy(policy)
    objects = [{"table": {"family": "inet", "name": TABLE}},
               {"set": {"family": "inet", "table": TABLE, "name": "blocked_v4", "type": "ipv4_addr",
                        "flags": ["interval"], "elem": [{"prefix": {"addr": str(net.network_address), "len": net.prefixlen}}
                         for net in map(ipaddress.IPv4Network, policy["blocked_ipv4"])]}}]
    for hook in ("output", "input", "forward"):
        objects.append({"chain": {"family": "inet", "table": TABLE, "name": hook, "type": "filter",
                                  "hook": hook, "prio": 0, "policy": "drop"}})
    ipv4 = _match({"meta": {"key": "nfproto"}}, "ipv4")
    ipv6 = _match({"meta": {"key": "nfproto"}}, "ipv6")
    output = [
        [ipv6, {"counter": None}, {"drop": None}],
        [ipv4, _match({"payload": {"protocol": "ip", "field": "daddr"}}, "@blocked_v4"), {"counter": None}, {"drop": None}],
        [_match({"meta": {"key": "oifname"}}, INTERFACE), ipv4, {"counter": None}, {"accept": None}],
    ]
    incoming = [[ipv6, {"counter": None}, {"drop": None}]]
    for state in ("established", "related"):
        incoming.append([_match({"meta": {"key": "iifname"}}, INTERFACE), ipv4,
                         _match({"ct": {"key": "state"}}, state), {"counter": None}, {"accept": None}])
    for chain, expressions in (("output", output), ("input", incoming)):
        for expr in expressions:
            objects.append({"rule": {"family": "inet", "table": TABLE, "chain": chain, "expr": expr}})
    return objects


def ruleset_document(policy: dict, replace: bool = False) -> dict:
    commands = ([{"delete": {"table": {"family": "inet", "name": TABLE}}}] if replace else [])
    return {"nftables": commands + [{"add": obj} for obj in ruleset_objects(policy)]}


def _canonical_ruleset(document: dict) -> list[dict]:
    if not isinstance(document, dict) or set(document) != {"nftables"} or not isinstance(document["nftables"], list):
        raise EgressError("Readback nft non valido")
    result = []
    for obj in document["nftables"]:
        if not isinstance(obj, dict) or len(obj) != 1:
            raise EgressError("Oggetto nft non riconosciuto")
        kind, body = next(iter(obj.items()))
        if kind == "metainfo":
            continue
        if kind not in ("table", "set", "chain", "rule") or not isinstance(body, dict):
            raise EgressError("Oggetto nft inatteso")
        body = {key: value for key, value in body.items() if key != "handle"}
        if kind == "set":
            elems = []
            for elem in body.get("elem", []):
                if isinstance(elem, str):
                    elems.append(str(ipaddress.IPv4Network(elem if "/" in elem else elem + "/32")))
                elif isinstance(elem, dict) and set(elem) == {"prefix"} and set(elem["prefix"]) == {"addr", "len"}:
                    elems.append(str(ipaddress.IPv4Network(f"{elem['prefix']['addr']}/{elem['prefix']['len']}")))
                elif isinstance(elem, dict) and set(elem) == {"range"} and len(elem["range"]) == 2:
                    elems.extend(str(net) for net in ipaddress.summarize_address_range(
                        ipaddress.IPv4Address(elem["range"][0]), ipaddress.IPv4Address(elem["range"][1])))
                else:
                    raise EgressError("Elemento deny-set nft non riconosciuto")
            body["elem"] = _networks(elems)
        if kind == "rule":
            expressions = []
            for expr in body.get("expr", []):
                if isinstance(expr, dict) and "counter" in expr:
                    counter = expr["counter"]
                    if set(expr) != {"counter"} or (counter is not None and
                        (not isinstance(counter, dict) or set(counter) != {"packets", "bytes"} or
                         any(type(value) is not int or value < 0 for value in counter.values()))):
                        raise EgressError("Contatore nft non valido")
                    expressions.append({"counter": None})
                else:
                    expressions.append(expr)
            # nft suppresses an explicit nfproto dependency when an IPv4
            # payload match already implies it. Normalize ONLY our exact
            # destination-set rule; never discard guards on general accepts.
            destination = _match({"payload": {"protocol": "ip", "field": "daddr"}}, "@blocked_v4")
            if destination in expressions:
                guard = _match({"meta": {"key": "nfproto"}}, "ipv4")
                expressions = [expr for expr in expressions if expr != guard]
            body["expr"] = expressions
        result.append({kind: body})
    # nft groups rules beside their chain; keep rule order within each chain.
    result.sort(key=lambda obj: (next(iter(obj)), json.dumps({k: v for k, v in next(iter(obj.values())).items() if k != "expr"}, sort_keys=True)))
    return result


def verify_ruleset(document: dict, policy: dict) -> dict:
    try:
        actual = _canonical_ruleset(document)
        expected = _canonical_ruleset({"nftables": ruleset_objects(policy)})
    except (ValueError, TypeError, KeyError) as exc:
        raise EgressError("Readback nft malformato") from exc
    if actual != expected:
        raise EgressError("Regole nft effettive divergono dalla policy autorizzata")
    return {"verified": True, "sha256": digest({"nftables": actual}), "ruleset": document,
            "ipv6": "drop", "input": "established-related-only", "output": "public-ipv4-only",
            "forward": "drop", "dns_rebinding": "destination-packet-filtered", "host_firewall_modified": False}


def install_firewall(policy: dict, host_net: str, replace: bool = False,
                     previous_policy: dict | None = None) -> dict:
    """Must never be called in the host netns, even accidentally."""
    if os.readlink("/proc/self/ns/net") == host_net:
        raise EgressError("Vietato configurare nft nel namespace host")
    before = json.loads(subprocess.check_output(["/usr/sbin/nft", "-j", "list", "ruleset"], timeout=5))
    if replace:
        # A single atomic transaction replaces only our verified private table.
        if previous_policy is None:
            raise EgressError("Policy precedente richiesta per sostituzione firewall")
        verify_ruleset(before, previous_policy)
    elif _canonical_ruleset(before):
        raise EgressError("Namespace nuovo contiene già regole nft")
    subprocess.run(["/usr/sbin/nft", "-j", "-f", "-"], input=json.dumps(ruleset_document(policy, replace)).encode(),
                   check=True, capture_output=True, timeout=5)
    readback = subprocess.check_output(["/usr/sbin/nft", "-j", "list", "ruleset"], timeout=5)
    if len(readback) > MAX_JSON:
        raise EgressError("Readback nft troppo grande")
    return verify_ruleset(json.loads(readback), policy)


def discover_public_identity(policy: dict) -> dict:
    """No sample/QEMU exists yet. Failed or disagreeing discovery is fail-closed."""
    context = ssl.create_default_context(cafile="/etc/ssl/certs/ca-certificates.crt")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    found = []
    for url in IDENTITY_URLS:
        with opener.open(url, timeout=5) as response:
            if response.status != 200 or response.geturl() != url:
                raise EgressError("Identità pubblica: risposta/redirect non autorizzato")
            value = response.read(65)
        if len(value) > 64:
            raise EgressError("Identità pubblica: risposta eccessiva")
        address = value.decode("ascii").strip()
        if not is_public_ipv4(address):
            raise EgressError("Identità pubblica: indirizzo non pubblico")
        found.append(address)
    if len(set(found)) != 1:
        raise EgressError("Identità pubblica host ambigua; accesso Internet rifiutato")
    return with_public_identity(policy, found[0])


def atomic_json(path: Path, value: dict) -> None:
    temporary = path.with_name(path.name + ".tmp-" + os.urandom(8).hex())
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream)
    os.replace(temporary, path)


def read_json(path: Path) -> dict:
    if path.is_symlink() or path.stat().st_size > MAX_JSON:
        raise EgressError("Handshake non valido")
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise EgressError("Handshake non riconosciuto")
    return value


def capabilities_are_dropped(proof: dict) -> bool:
    try:
        status = proof["capability_status"]
        return (proof["capabilities_dropped"] is True and proof["no_new_privs"] is True
                and all(int(status[name], 16) == 0 for name in ("CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb"))
                and status["NoNewPrivs"] == "1")
    except (KeyError, TypeError, ValueError):
        return False


def validate_network_proof(proof: dict, base_policy: dict, namespaces: dict) -> bool:
    """Parent verifies actual rule semantics, not a self-asserted firewall boolean."""
    try:
        identity = proof["public_identity"]
        final = with_public_identity(base_policy, identity["ipv4"])
        firewall = verify_ruleset(proof["firewall"]["ruleset"], final)
        return (proof["network_mode"] == "internet" and proof["guest_internet"] is True
                and proof["guest_host"] is False and proof["guest_lan"] is False
                and proof["slirp_restrict"] is False and proof["interfaces"] == ["lo", INTERFACE]
                and proof["base_policy_sha256"] == digest(base_policy) and proof["policy_sha256"] == digest(final)
                and identity == final["public_identity"] and proof["firewall"]["verified"] is True
                and proof["firewall"]["sha256"] == firewall["sha256"]
                and proof["gateway"]["ready"] is True and proof["gateway"]["nonce"] == base_policy["nonce"]
                and proof["gateway"]["net_namespace"] == namespaces["net_namespace"] == proof["net_namespace"]
                and proof["gateway"]["user_namespace"] == namespaces["user_namespace"] == proof["user_namespace"]
                and proof["gateway"]["sandbox"] is True and proof["gateway"]["seccomp"] is True
                and proof["gateway"]["disable_host_loopback"] is True and proof["gateway"]["disable_dns"] is True
                and proof["gateway"] == namespaces["gateway_evidence"]
                and proof["resolvers"] == RESOLVERS and proof["outer_address"] == OUTER_ADDRESS
                and proof["outer_gateway"] == OUTER_GATEWAY and proof["public_identity_state"] == "confirmed-and-blocked")
    except (KeyError, TypeError, ValueError, EgressError):
        return False


class EgressGateway:
    """Nonce-bound descriptor handshake and always-reaped slirp lifetime."""
    def __init__(self, run_dir: Path, nonce: str, targets: list | None = None):
        self.run_dir = Path(run_dir).resolve()
        self.nonce = nonce
        self.policy = snapshot_policy(nonce, targets)
        self.policy_path = self.run_dir / "egress-policy.json"
        self.resolver_path = self.run_dir / "egress-resolv.conf"
        self.proc = None
        self.namespace_proc = None
        self.namespaces = {}
        self._fds = set()
        self._log = None
        self._watcher = None
        self._closing = threading.Event()
        self._close_lock = threading.Lock()
        atomic_json(self.policy_path, self.policy)
        fd = os.open(self.resolver_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write("".join(f"nameserver {ip}\n" for ip in RESOLVERS) + "options timeout:1 attempts:2\n")

    def _pipe(self):
        fds = os.pipe2(os.O_CLOEXEC)
        self._fds.update(fds)
        return fds

    def _close_fd(self, fd):
        if fd in self._fds:
            self._fds.remove(fd)
            with contextlib.suppress(OSError):
                os.close(fd)

    def _read_info(self, fd, deadline):
        data = bytearray()
        while time.monotonic() < deadline:
            if self.namespace_proc.poll() is not None:
                raise EgressError("Namespace terminato prima dell'handshake")
            if not select.select([fd], [], [], min(0.1, max(0, deadline - time.monotonic())))[0]:
                continue
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > 8192:
                raise EgressError("bwrap info-fd eccessivo")
            try:
                value = json.loads(data)
            except ValueError:
                continue
            pid = value.get("child-pid")
            if type(pid) is not int or pid <= 1:
                raise EgressError("bwrap child-pid non valido")
            return pid
        raise EgressError("Timeout bwrap info-fd")

    def _wait_request(self, deadline):
        path = self.run_dir / "egress-request.json"
        while time.monotonic() < deadline:
            if self.namespace_proc.poll() is not None:
                raise EgressError("Runner terminato prima della verifica firewall")
            if path.exists():
                request = read_json(path)
                if (request.get("nonce") != self.nonce or request.get("base_policy_sha256") != digest(self.policy)
                        or request.get("net_namespace") != self.namespaces["net_namespace"]
                        or request.get("user_namespace") != self.namespaces["user_namespace"]):
                    raise EgressError("Handshake namespace/policy non corrispondente")
                verify_ruleset(request["firewall"]["ruleset"], self.policy)
                return
            time.sleep(0.05)
        raise EgressError("Timeout verifica firewall prima del gateway")

    def start(self, launcher):
        """launcher(info_fd) must Popen bwrap with that descriptor in pass_fds."""
        try:
            info_r, info_w = self._pipe()
            self.namespace_proc = launcher(info_w)
            self._close_fd(info_w)
            deadline = time.monotonic() + 20
            pid = self._read_info(info_r, deadline)
            self._close_fd(info_r)
            for kind in ("user", "net"):
                fd = os.open(f"/proc/{pid}/ns/{kind}", os.O_RDONLY | os.O_CLOEXEC)
                self._fds.add(fd)
                identity = os.readlink(f"/proc/self/fd/{fd}")
                if identity == os.readlink(f"/proc/self/ns/{kind}"):
                    raise EgressError("Gateway non può usare namespace host")
                self.namespaces[kind + "_namespace"] = identity
                self.namespaces[kind + "_fd"] = fd
            self._wait_request(deadline)
            ready_r, ready_w = self._pipe()
            exit_r, exit_w = self._pipe()
            binary = shutil.which("slirp4netns")
            if not binary:
                raise EgressError("slirp4netns non disponibile")
            fds = (ready_w, exit_r, self.namespaces["user_fd"], self.namespaces["net_fd"])
            command = [binary, "--configure", "--mtu=1500", "--cidr=" + OUTER_CIDR,
                       "--enable-sandbox", "--enable-seccomp", "--disable-host-loopback", "--disable-dns",
                       "--netns-type=path", "--userns-path=/proc/self/fd/" + str(self.namespaces["user_fd"]),
                       "--ready-fd=" + str(ready_w), "--exit-fd=" + str(exit_r),
                       "/proc/self/fd/" + str(self.namespaces["net_fd"]), INTERFACE]
            fd = os.open(self.run_dir / "egress.log", os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            self._log = os.fdopen(fd, "ab", buffering=0)
            self.proc = subprocess.Popen([sys.executable, "-I", str(Path(__file__).resolve()), "--gateway-exec",
                                          "--userns-fd=" + str(self.namespaces["user_fd"]), *command],
                                         stdin=subprocess.DEVNULL, stdout=self._log, stderr=self._log,
                                         close_fds=True, pass_fds=fds, start_new_session=True,
                                         env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": "/nonexistent"})
            for inherited in fds:
                self._close_fd(inherited)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if self.proc.poll() is not None or self.namespace_proc.poll() is not None:
                    raise EgressError("Gateway/namespace terminato durante l'avvio")
                if select.select([ready_r], [], [], 0.1)[0]:
                    if os.read(ready_r, 8) != b"1":
                        raise EgressError("Gateway readiness non valida")
                    break
            else:
                raise EgressError("Timeout gateway")
            self._close_fd(ready_r)
            status = dict(line.split(":", 1) for line in Path(f"/proc/{self.proc.pid}/status").read_text().splitlines() if ":" in line)
            mount = os.readlink(f"/proc/{self.proc.pid}/ns/mnt")
            host_mount = os.readlink("/proc/self/ns/mnt")
            cap_status = {name: status[name].strip() for name in ("CapEff", "CapPrm", "CapInh", "CapAmb")}
            if (status.get("Seccomp", "").strip() != "2" or status.get("NoNewPrivs", "").strip() != "1"
                    or mount == host_mount or any(int(value, 16) & ~(1 << 10) for value in cap_status.values())):
                raise EgressError("Sandbox/seccomp/capability gateway non effettivi")
            self.assert_live()
            self.namespaces["gateway_evidence"] = {
                "nonce": self.nonce, "ready": True, "base_policy_sha256": digest(self.policy),
                "net_namespace": self.namespaces["net_namespace"], "user_namespace": self.namespaces["user_namespace"],
                "sandbox": True, "seccomp": True, "disable_host_loopback": True, "disable_dns": True,
                "mount_namespace": mount, "host_mount_namespace": host_mount,
                "capability_status": cap_status, "no_new_privs": True,
                "cidr": OUTER_CIDR, "interface": INTERFACE, "pid": self.proc.pid,
            }
            atomic_json(self.run_dir / "egress-ready.json", self.namespaces["gateway_evidence"])
            self._watcher = threading.Thread(target=self._watch, name="sandbox-egress", daemon=True)
            self._watcher.start()
            return self.namespace_proc
        except BaseException:
            self.close(terminate_namespace=True)
            raise

    def assert_live(self):
        if self._closing.is_set() or self.proc is None or self.proc.poll() is not None:
            raise EgressError("Gateway isolato non attivo; trasferimento guest rifiutato")

    def _watch(self):
        deadline = time.monotonic() + MAX_SECONDS
        while not self._closing.wait(0.1):
            if self.namespace_proc.poll() is not None:
                self.close()
                return
            gateway_proc = self.proc
            if gateway_proc is None or gateway_proc.poll() is not None or time.monotonic() >= deadline:
                self.close(terminate_namespace=True)
                return

    @staticmethod
    def _terminate(proc):
        if proc is None:
            return
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, signal.SIGTERM)
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=3)
        finally:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(proc.pid, signal.SIGKILL)

    def close(self, terminate_namespace=False):
        with self._close_lock:
            self._closing.set()
            try:
                if terminate_namespace:
                    self._terminate(self.namespace_proc)
            finally:
                for fd in tuple(self._fds):
                    self._close_fd(fd)
                try:
                    if self.proc is not None:
                        self._terminate(self.proc)
                finally:
                    self.proc = None
                    if self._log is not None:
                        self._log.close()
                        self._log = None
        if self._watcher is not None and self._watcher is not threading.current_thread():
            self._watcher.join(timeout=5)


def probe_namespace(run_dir: Path, base_dir: Path, *, network="internet", targets=None) -> dict:
    """Boot-free proof. Optional TCP targets: {address, port, allowed}; max32.

    A successful Internet probe includes public identity discovery, verified nft,
    actual tap/routes, dropped capabilities, and any requested connectivity tests.
    All subprocesses and descriptors are closed on every outcome.
    """
    from .namespace import bwrap_command
    run_dir = Path(run_dir).resolve()
    run_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
    run_dir.chmod(0o700)
    nonce = os.urandom(16).hex()
    gateway = None
    proc = None
    fd = os.open(run_dir / "namespace-probe.log", os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "ab", buffering=0) as stream:
        try:
            if network == "internet":
                gateway = EgressGateway(run_dir, nonce, targets)
                proc = gateway.start(lambda info: subprocess.Popen(
                    bwrap_command(run_dir, base_dir, nonce, policy_path=gateway.policy_path, info_fd=info),
                    stdout=stream, stderr=stream, stdin=subprocess.DEVNULL, pass_fds=(info,), start_new_session=True))
            elif network == "offline":
                if targets:
                    raise EgressError("Sonde personalizzate richiedono modalità Internet")
                proc = subprocess.Popen(bwrap_command(run_dir, base_dir, nonce), stdout=stream, stderr=stream,
                                        stdin=subprocess.DEVNULL, start_new_session=True)
            else:
                raise EgressError("Modalità rete sconosciuta")
            proc.wait(timeout=75)
            proof = read_json(run_dir / "namespace-probe.json")
            if (proc.returncode != 0 or proof.get("nonce") != nonce or proof.get("confirmed") is not True
                    or proof.get("capabilities_dropped") is not True or proof.get("no_new_privs") is not True
                    or proof.get("host_net_namespace") != os.readlink("/proc/self/ns/net")
                    or proof.get("host_user_namespace") != os.readlink("/proc/self/ns/user")
                    or proof.get("net_namespace") == proof.get("host_net_namespace")
                    or proof.get("user_namespace") == proof.get("host_user_namespace")
                    or not capabilities_are_dropped(proof)):
                raise EgressError(proof.get("error", "Attestazione probe non valida"))
            if gateway and not validate_network_proof(proof, gateway.policy, gateway.namespaces):
                raise EgressError("Attestazione firewall probe non valida")
            return proof
        finally:
            try:
                EgressGateway._terminate(proc)
            finally:
                if gateway:
                    gateway.close()


def _gateway_exec(argv):
    # A small exec wrapper avoids preexec_fn in the threaded API process.
    if len(argv) < 2 or not argv[0].startswith("--userns-fd=") or Path(argv[1]).name != "slirp4netns":
        raise EgressError("Eseguibile/namespace gateway non autorizzato")
    fd = int(argv[0].split("=", 1)[1])
    if fd < 3 or not os.readlink(f"/proc/self/fd/{fd}").startswith("user:["):
        raise EgressError("Descriptor user namespace gateway non valido")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() == 1:
        raise EgressError("Parent-death gateway non impostato")
    host_net = os.readlink("/proc/self/ns/net")
    target_user = os.readlink(f"/proc/self/fd/{fd}")
    if target_user == os.readlink("/proc/self/ns/user"):
        raise EgressError("User namespace host vietato per gateway")
    # slirp 1.2.1's path-mode parent ignores --userns-path for sandbox setup
    # (main.c: nsenter(target_pid=0,NULL,NULL,true)). Enter the pinned USER
    # namespace explicitly; retain the HOST netns for user-mode outbound
    # sockets. The native sandbox then works as mapped uid0 and drops all
    # capabilities except NET_BIND_SERVICE before signalling ready.
    if libc.setns(fd, 0x10000000) != 0:  # CLONE_NEWUSER
        raise OSError(ctypes.get_errno(), "setns user gateway fallito")
    if (os.geteuid() != 0 or os.getegid() != 0 or os.readlink("/proc/self/ns/user") != target_user
            or os.readlink("/proc/self/ns/net") != host_net):
        raise EgressError("Confinamento user/egress gateway non confermato")
    argv = argv[1:]
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    resource.setrlimit(resource.RLIMIT_FSIZE, (4 * 1024 ** 2, 4 * 1024 ** 2))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 ** 2, 512 * 1024 ** 2))
    resource.setrlimit(resource.RLIMIT_CPU, (1800, 1800))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.execv(argv[0], argv)


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--gateway-exec":
        _gateway_exec(sys.argv[2:])
    else:
        raise SystemExit("egress: solo wrapper gateway")

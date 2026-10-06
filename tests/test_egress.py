import copy
import ipaddress
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from lab import egress, namespace


@pytest.fixture
def policy():
    addresses = [
        {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]},
        {"ifname": "eth0", "addr_info": [{"family": "inet", "local": "192.168.7.2", "prefixlen": 24},
                                       {"family": "inet6", "local": "2001:db8::2", "prefixlen": 64}]},
        {"ifname": "wan", "addr_info": [{"family": "inet", "local": "45.67.89.10", "prefixlen": 24}]},
    ]
    routes = [{"dst": "default", "gateway": "192.168.7.1", "dev": "eth0"},
              {"dst": "192.168.7.0/24", "dev": "eth0"},
              {"dst": "93.184.216.0/24", "dev": "eth0"}]
    return egress.policy_from_snapshot(addresses, routes, [], "nonce-test")


def readback(policy):
    document = {"nftables": [{"metainfo": {"json_schema_version": 1}}] + copy.deepcopy(egress.ruleset_objects(policy))}
    for index, obj in enumerate(document["nftables"][1:]):
        body = next(iter(obj.values()))
        body["handle"] = index + 1
        if "rule" in obj:
            for expr in body["expr"]:
                if "counter" in expr:
                    expr["counter"] = {"packets": 7, "bytes": 420}
    return document


@pytest.mark.parametrize("address", [
    "0.0.0.0", "0.1.2.3", "10.1.2.3", "100.64.0.1", "100.127.255.254", "127.0.0.1",
    "169.254.169.254", "172.16.0.1", "172.31.255.254", "192.0.0.9", "192.0.2.1",
    "192.88.99.1", "192.168.1.1", "198.18.1.1", "198.19.255.254", "198.51.100.1",
    "203.0.113.1", "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255",
    "::1", "::ffff:8.8.8.8", "2001:4860:4860::8888", "not-an-address", "2130706433",
    "45.67.89.10", "45.67.89.11", "93.184.216.34", "10.77.0.2", "10.77.0.3",
])
def test_reserved_private_host_public_and_connected_routes_denied(policy, address):
    assert not egress.destination_allowed(address, policy)


@pytest.mark.parametrize("address", ["1.1.1.1", "9.9.9.9", "8.8.8.8", "93.184.215.34"])
def test_public_destinations_allowed(policy, address):
    assert egress.destination_allowed(address, policy)


def test_dns_rebinding_and_redirect_cannot_grant_address_exception(policy):
    # The same logical hostname may rotate from public to private/host. Decisions
    # depend only on each packet destination, never an allowlisted hostname.
    answers = ["8.8.8.8", "192.168.7.2", "127.0.0.1", "45.67.89.10", "169.254.169.254"]
    assert [egress.destination_allowed(ip, policy) for ip in answers] == [True, False, False, False, False]
    output = [obj["rule"]["expr"] for obj in egress.ruleset_objects(policy)
              if "rule" in obj and obj["rule"]["chain"] == "output"]
    assert output[1][-1] == {"drop": None}
    assert output[2][-1] == {"accept": None}
    assert not any("ct" in json.dumps(rule) for rule in output)


@pytest.mark.parametrize("mutate", [
    lambda value: value.update(resolvers=["192.168.7.1"]),
    lambda value: value.update(interface="eth0"),
    lambda value: value.update(outer_cidr="10.0.2.0/24"),
    lambda value: value.update(blocked_ipv4=[]),
    lambda value: value.update(blocked_ipv4=["0.0.0.0/8"]),
    lambda value: value.update(blocked_ipv4=["8.8.8.8; accept"]),
    lambda value: value.update(version=True),
    lambda value: value.update(unrecognized=True),
    lambda value: value.update(probe_targets=[{"address": "127.0.0.1", "port": True, "allowed": False}]),
    lambda value: value.update(public_identity={"confirmed": False}),
])
def test_malformed_or_permissive_configuration_fails_closed(policy, mutate):
    invalid = copy.deepcopy(policy)
    mutate(invalid)
    with pytest.raises(egress.EgressError):
        egress.validate_policy(invalid)


@pytest.mark.parametrize("addresses,routes4,routes6", [
    ([], [], []),
    ([{"ifname": "eth0", "addr_info": "unknown"}], [], []),
    ([{"ifname": "eth0", "addr_info": [{"family": "other"}]}], [], []),
    ([{"ifname": "eth0", "addr_info": [{"family": "inet", "local": "192.168.1.2", "prefixlen": 33}]}], [], []),
    ([{"ifname": "eth0", "addr_info": [{"family": "inet", "local": "192.168.1.2", "prefixlen": 24}]}],
     [{"dst": "default"}], []),
    ([{"ifname": "eth0", "addr_info": [{"family": "inet", "local": "192.168.1.2", "prefixlen": 24}]}],
     [{"dst": "default", "dev": "eth0"}, {"dst": "garbage"}], []),
    ([{"ifname": "eth0", "addr_info": [{"family": "inet", "local": "192.168.1.2", "prefixlen": 24}]}],
     [{"dst": "default", "dev": "eth0", "gateway": "::1"}], []),
])
def test_unknown_host_snapshot_never_degrades_to_public_only_defaults(addresses, routes4, routes6):
    with pytest.raises(egress.EgressError):
        egress.policy_from_snapshot(addresses, routes4, routes6, "test")


def test_actual_readback_verified_despite_runtime_counters_and_handles(policy):
    actual = readback(policy)
    result = egress.verify_ruleset(actual, policy)
    assert result["verified"] is True
    assert result["ipv6"] == "drop"
    assert result["host_firewall_modified"] is False
    assert result["sha256"] == egress.verify_ruleset({"nftables": egress.ruleset_objects(policy)}, policy)["sha256"]


def test_nft_bare_ipv4_and_prefix_elements_are_semantically_identical(policy):
    final = egress.with_public_identity(policy, "8.8.4.4")
    actual = readback(final)
    for obj in actual["nftables"]:
        if "set" in obj:
            obj["set"]["elem"] = [item["prefix"]["addr"] if item["prefix"]["len"] == 32 else item
                                  for item in obj["set"]["elem"]]
    assert egress.verify_ruleset(actual, final)["verified"]


@pytest.mark.parametrize("mutation", ["allow_private", "output_accept", "extra_table", "missing_rule", "reorder", "ipv6_accept"])
def test_actual_readback_rejects_fail_open_or_malformed_rules(policy, mutation):
    actual = readback(policy)
    rules = [obj["rule"] for obj in actual["nftables"] if "rule" in obj and obj["rule"]["chain"] == "output"]
    if mutation == "allow_private":
        rules[1]["expr"][-1] = {"accept": None}
    elif mutation == "output_accept":
        next(obj["chain"] for obj in actual["nftables"] if "chain" in obj and obj["chain"]["name"] == "output")["policy"] = "accept"
    elif mutation == "extra_table":
        actual["nftables"].append({"table": {"family": "inet", "name": "unexpected"}})
    elif mutation == "missing_rule":
        actual["nftables"].remove(next(obj for obj in actual["nftables"] if obj.get("rule") is rules[1]))
    elif mutation == "reorder":
        rules[1]["expr"], rules[2]["expr"] = rules[2]["expr"], rules[1]["expr"]
    elif mutation == "ipv6_accept":
        rules[0]["expr"][-1] = {"accept": None}
    with pytest.raises(egress.EgressError):
        egress.verify_ruleset(actual, policy)


def test_firewall_install_refuses_to_even_inspect_host_rules(policy, monkeypatch):
    monkeypatch.setattr(egress.os, "readlink", lambda path: "net:[host]")
    command = Mock()
    monkeypatch.setattr(egress.subprocess, "check_output", command)
    monkeypatch.setattr(egress.subprocess, "run", command)
    with pytest.raises(egress.EgressError, match="host"):
        egress.install_firewall(policy, "net:[host]")
    command.assert_not_called()


def test_firewall_load_requires_matching_actual_readback(policy, monkeypatch):
    monkeypatch.setattr(egress.os, "readlink", lambda path: "net:[private]")
    query = Mock(side_effect=[b'{"nftables": []}', json.dumps(readback(policy)).encode()])
    load = Mock(return_value=SimpleNamespace(returncode=0))
    monkeypatch.setattr(egress.subprocess, "check_output", query)
    monkeypatch.setattr(egress.subprocess, "run", load)
    assert egress.install_firewall(policy, "net:[host]")["verified"]
    assert load.call_args.args[0] == ["/usr/sbin/nft", "-j", "-f", "-"]
    assert json.loads(load.call_args.kwargs["input"]) == egress.ruleset_document(policy)


def test_firewall_load_error_never_produces_verified_evidence(policy, monkeypatch):
    monkeypatch.setattr(egress.os, "readlink", lambda path: "net:[private]")
    monkeypatch.setattr(egress.subprocess, "check_output", lambda *a, **kw: b'{"nftables": []}')
    monkeypatch.setattr(egress.subprocess, "run", Mock(side_effect=RuntimeError("load denied")))
    with pytest.raises(RuntimeError, match="load denied"):
        egress.install_firewall(policy, "net:[host]")


def echo_response(value, url):
    response = Mock(status=200)
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    response.geturl.return_value = url
    response.read.return_value = value
    return response


def test_public_nat_reflection_identity_is_measured_and_denied(policy, monkeypatch):
    opener = Mock()
    opener.open.side_effect = [echo_response(b"8.8.4.4\n", url) for url in egress.IDENTITY_URLS]
    monkeypatch.setattr(egress.ssl, "create_default_context", Mock())
    monkeypatch.setattr(egress.urllib.request, "build_opener", lambda *a: opener)
    final = egress.discover_public_identity(policy)
    assert final["public_identity"]["confirmed"] is True
    assert not egress.destination_allowed("8.8.4.4", final)
    assert egress.destination_allowed("8.8.8.8", final)
    assert opener.open.call_args_list[0].kwargs["timeout"] == 5


@pytest.mark.parametrize("values", [[b"8.8.4.4", b"8.8.8.8"], [b"192.168.1.1", b"192.168.1.1"], [b"x" * 65, b"x" * 65]])
def test_unknown_or_ambiguous_nat_identity_fails_closed(policy, monkeypatch, values):
    opener = Mock()
    opener.open.side_effect = [echo_response(value, url) for value, url in zip(values, egress.IDENTITY_URLS)]
    monkeypatch.setattr(egress.ssl, "create_default_context", Mock())
    monkeypatch.setattr(egress.urllib.request, "build_opener", lambda *a: opener)
    with pytest.raises(egress.EgressError):
        egress.discover_public_identity(policy)


def test_gateway_launcher_failure_closes_every_pipe(policy, tmp_path, monkeypatch):
    monkeypatch.setattr(egress, "snapshot_policy", lambda *a: policy)
    gateway = egress.EgressGateway(tmp_path, policy["nonce"])
    held = []
    original_pipe = gateway._pipe
    def tracked_pipe():
        pair = original_pipe()
        held.extend(pair)
        return pair
    monkeypatch.setattr(gateway, "_pipe", tracked_pipe)
    with pytest.raises(OSError, match="bwrap failed"):
        gateway.start(Mock(side_effect=OSError("bwrap failed")))
    assert gateway._fds == set()
    for fd in held:
        with pytest.raises(OSError):
            os.fstat(fd)
    gateway.close()


def test_gateway_firewall_handshake_failure_reaps_namespace(policy, tmp_path, monkeypatch):
    monkeypatch.setattr(egress, "snapshot_policy", lambda *a: policy)
    gateway = egress.EgressGateway(tmp_path, policy["nonce"])
    proc = Mock()
    proc.poll.return_value = None
    monkeypatch.setattr(gateway, "_read_info", lambda *a: os.getpid())
    original_readlink = os.readlink
    monkeypatch.setattr(egress.os, "readlink", lambda path: original_readlink(path) + ("-private" if "/fd/" in path else ""))
    monkeypatch.setattr(gateway, "_wait_request", Mock(side_effect=egress.EgressError("invalid firewall")))
    terminate = Mock()
    monkeypatch.setattr(gateway, "_terminate", terminate)
    with pytest.raises(egress.EgressError, match="invalid firewall"):
        gateway.start(lambda info: proc)
    terminate.assert_any_call(proc)
    assert gateway._fds == set()
    assert gateway.proc is None


def test_gateway_close_reaps_slirp_and_closes_logs_even_if_namespace_kill_fails(policy, tmp_path, monkeypatch):
    monkeypatch.setattr(egress, "snapshot_policy", lambda *a: policy)
    gateway = egress.EgressGateway(tmp_path, policy["nonce"])
    gateway.namespace_proc = Mock()
    slirp = gateway.proc = Mock()
    gateway._log = Mock()
    log = gateway._log
    gateway._pipe()
    terminate = Mock(side_effect=[RuntimeError("namespace kill failed"), None])
    monkeypatch.setattr(gateway, "_terminate", terminate)
    with pytest.raises(RuntimeError, match="namespace kill failed"):
        gateway.close(terminate_namespace=True)
    assert terminate.call_args_list[1].args == (slirp,)
    assert gateway._fds == set()
    log.close.assert_called_once()
    assert gateway.proc is None
    with pytest.raises(egress.EgressError):
        gateway.assert_live()


def test_resolver_and_policy_are_read_only_inside_run_mount(policy, tmp_path):
    path = tmp_path / "egress-policy.json"
    path.write_text(json.dumps(policy))
    path.with_name("egress-resolv.conf").write_text("nameserver 1.1.1.1\n")
    command = namespace.bwrap_command(tmp_path, tmp_path / "base", policy["nonce"], policy_path=path, info_fd=77)
    run_bind = command.index("--bind")
    for source, destination in ((str(path), str(path)), (str(path), "/egress-policy.json"),
                                (str(path.with_name("egress-resolv.conf")), "/etc/resolv.conf"),
                                (str(path.with_name("egress-resolv.conf")), str(path.with_name("egress-resolv.conf")))):
        indices = [index for index, value in enumerate(command) if value == "--ro-bind" and command[index + 1:index + 3] == [source, destination]]
        assert indices and indices[0] > run_bind
    assert command[command.index("--info-fd") + 1] == "77"
    assert "--share-net" not in command


def test_capability_evidence_requires_actual_zero_values():
    proof = {"capabilities_dropped": True, "no_new_privs": True,
             "capability_status": {name: "0000000000000000" for name in ("CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb")}}
    proof["capability_status"]["NoNewPrivs"] = "1"
    assert egress.capabilities_are_dropped(proof)
    proof["capability_status"]["CapEff"] = "1000"
    assert not egress.capabilities_are_dropped(proof)


def test_gateway_bad_readiness_reaps_slirp_and_namespace_with_no_ready_marker(policy, tmp_path, monkeypatch):
    monkeypatch.setattr(egress, "snapshot_policy", lambda *a: policy)
    gateway = egress.EgressGateway(tmp_path, policy["nonce"])
    namespace_proc, slirp = Mock(), Mock()
    namespace_proc.poll.return_value = slirp.poll.return_value = None
    monkeypatch.setattr(gateway, "_read_info", lambda *a: os.getpid())
    monkeypatch.setattr(gateway, "_wait_request", lambda *a: None)
    original_readlink = os.readlink
    monkeypatch.setattr(egress.os, "readlink", lambda path: original_readlink(path) + ("-private" if "/fd/" in path else ""))
    monkeypatch.setattr(egress.shutil, "which", lambda name: "/usr/bin/slirp4netns")
    popen = Mock(return_value=slirp)
    monkeypatch.setattr(egress.subprocess, "Popen", popen)
    monkeypatch.setattr(egress.select, "select", lambda readers, *a: (readers, [], []))
    monkeypatch.setattr(egress.os, "read", lambda *a: b"invalid")
    terminate = Mock()
    monkeypatch.setattr(gateway, "_terminate", terminate)
    with pytest.raises(egress.EgressError, match="readiness"):
        gateway.start(lambda info: namespace_proc)
    terminate.assert_any_call(slirp)
    terminate.assert_any_call(namespace_proc)
    assert not (tmp_path / "egress-ready.json").exists()
    assert gateway._fds == set() and gateway._log is None
    command = popen.call_args.args[0]
    for option in ("--enable-sandbox", "--enable-seccomp", "--disable-host-loopback", "--disable-dns",
                   "--netns-type=path", "--cidr=10.77.0.0/24"):
        assert option in command
    assert "--enable-ipv6" not in command and "--api-socket" not in " ".join(command)
    assert set(popen.call_args.kwargs["env"]) == {"PATH", "LANG", "HOME"}


def test_gateway_watchdog_terminates_namespace_if_helper_dies(policy, tmp_path, monkeypatch):
    monkeypatch.setattr(egress, "snapshot_policy", lambda *a: policy)
    gateway = egress.EgressGateway(tmp_path, policy["nonce"])
    gateway.namespace_proc = Mock()
    gateway.namespace_proc.poll.return_value = None
    gateway.proc = Mock()
    gateway.proc.poll.return_value = 1
    monkeypatch.setattr(gateway._closing, "wait", lambda timeout: False)
    close = Mock()
    monkeypatch.setattr(gateway, "close", close)
    gateway._watch()
    close.assert_called_once_with(terminate_namespace=True)


def test_firewall_replacement_requires_verified_previous_policy(policy, monkeypatch):
    monkeypatch.setattr(egress.os, "readlink", lambda path: "net:[private]")
    monkeypatch.setattr(egress.subprocess, "check_output", lambda *a, **kw: json.dumps(readback(policy)).encode())
    load = Mock()
    monkeypatch.setattr(egress.subprocess, "run", load)
    with pytest.raises(egress.EgressError, match="precedente"):
        egress.install_firewall(egress.with_public_identity(policy, "8.8.4.4"), "net:[host]", replace=True)
    load.assert_not_called()


def test_nft_readback_suppresses_only_implied_ipv4_destination_guard(policy):
    actual = readback(policy)
    for obj in actual["nftables"]:
        if "rule" in obj and any(expr.get("match", {}).get("left") ==
                                {"payload": {"protocol": "ip", "field": "daddr"}}
                                for expr in obj["rule"]["expr"]):
            obj["rule"]["expr"] = [expr for expr in obj["rule"]["expr"]
                                   if expr != {"match": {"op": "==", "left": {"meta": {"key": "nfproto"}}, "right": "ipv4"}}]
    assert egress.verify_ruleset(actual, policy)["verified"]
    # Removing an IPv4 guard from a generic accept is not equivalent.
    accept = next(obj["rule"] for obj in actual["nftables"] if "rule" in obj
                  and obj["rule"]["chain"] == "output" and obj["rule"]["expr"][-1] == {"accept": None})
    accept["expr"] = [expr for expr in accept["expr"]
                     if expr != {"match": {"op": "==", "left": {"meta": {"key": "nfproto"}}, "right": "ipv4"}}]
    with pytest.raises(egress.EgressError):
        egress.verify_ruleset(actual, policy)


def test_exec_wrapper_enters_only_pinned_userns_then_bounds_resources_before_slirp(monkeypatch):
    entered = False
    libc = Mock()
    libc.prctl.return_value = 0
    def setns(fd, kind):
        nonlocal entered
        entered = True
        return 0
    libc.setns.side_effect = setns
    monkeypatch.setattr(egress.ctypes, "CDLL", lambda *a, **kw: libc)
    def link(path):
        if path == "/proc/self/fd/17":
            return "user:[pinned]"
        if path == "/proc/self/ns/user":
            return "user:[pinned]" if entered else "user:[host]"
        if path == "/proc/self/ns/net":
            return "net:[host]"
        raise AssertionError(path)
    monkeypatch.setattr(egress.os, "readlink", link)
    monkeypatch.setattr(egress.os, "geteuid", lambda: 0)
    monkeypatch.setattr(egress.os, "getegid", lambda: 0)
    monkeypatch.setattr(egress.os, "getppid", lambda: 123)
    limit = Mock()
    monkeypatch.setattr(egress.resource, "setrlimit", limit)
    execute = Mock(side_effect=RuntimeError("mock exec only"))
    monkeypatch.setattr(egress.os, "execv", execute)
    args = ["/usr/bin/slirp4netns", "--enable-sandbox", "--enable-seccomp", "--netns-type=path",
            "--userns-path=/proc/self/fd/17", "/proc/self/fd/18", "tap0"]
    with pytest.raises(RuntimeError, match="mock exec"):
        egress._gateway_exec(["--userns-fd=17", *args])
    libc.setns.assert_called_once_with(17, 0x10000000)
    execute.assert_called_once_with(args[0], args)
    assert limit.call_count == 5
    limit.assert_any_call(egress.resource.RLIMIT_NOFILE, (256, 256))
    limit.assert_any_call(egress.resource.RLIMIT_AS, (512 * 1024 ** 2, 512 * 1024 ** 2))


def test_exec_wrapper_rejects_host_userns_without_exec_or_namespace_mutation(monkeypatch):
    libc = Mock()
    libc.prctl.return_value = 0
    monkeypatch.setattr(egress.ctypes, "CDLL", lambda *a, **kw: libc)
    monkeypatch.setattr(egress.os, "readlink", lambda path: "net:[host]" if path.endswith("/net") else "user:[host]")
    monkeypatch.setattr(egress.os, "getppid", lambda: 123)
    execute = Mock()
    monkeypatch.setattr(egress.os, "execv", execute)
    with pytest.raises(egress.EgressError, match="host vietato"):
        egress._gateway_exec(["--userns-fd=17", "/usr/bin/slirp4netns"])
    libc.setns.assert_not_called()
    execute.assert_not_called()


def test_host_snapshot_uses_pinned_ip_without_service_sbin_path(policy, monkeypatch):
    requested = []
    monkeypatch.setattr(egress.shutil, "which", lambda command: command if command == "/usr/sbin/ip" else None)
    def host_json(argv):
        requested.append(argv)
        if argv[1:] == ["-j", "addr", "show"]:
            return [{"ifname": "eth0", "addr_info": [{"family": "inet", "local": "192.168.7.2", "prefixlen": 24}]}]
        if "-4" in argv:
            return [{"dst": "default", "gateway": "192.168.7.1", "dev": "eth0"}]
        return []
    monkeypatch.setattr(egress, "_host_json", host_json)
    assert not egress.destination_allowed("192.168.7.2", egress.snapshot_policy("minimal-path"))
    assert len(requested) == 3 and all(argv[0] == "/usr/sbin/ip" for argv in requested)

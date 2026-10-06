import base64
import json
import os
from pathlib import Path
import shutil
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from lab import bootstrap, namespace, vm


@pytest.fixture
def runtime(tmp_path):
    base = tmp_path / "bases"
    base.mkdir()
    for name in ("clean.qcow2", "OVMF_VARS.fd", "tpm2-00.permall"):
        (base / name).write_bytes(b"clean-fixture")
    (base / "metadata.json").write_text(json.dumps({"ready": True, "capabilities": {}}))
    return vm.AnalysisVM(tmp_path / "run", base, {"id": "interactive", "interaction": True})


def test_qemu_command_has_only_private_isolated_hardware(runtime):
    command = runtime.qemu_command()
    text = " ".join(command)
    assert command[command.index("-m") + 1] == "4096"
    assert command[command.index("-smp") + 1] == "cores=2,threads=1,sockets=1"
    assert "restrict=on" in text
    assert "guestfwd=tcp:10.0.2.100:80-cmd:/usr/bin/python3 -I /runner.py --http-stdio" in text
    assert "tcp:127.0.0.1:18080" not in text
    assert str(runtime.run_dir / "network.pcap") in text
    assert "unix:" + str(runtime.vnc_socket) in text
    assert str(runtime.overlay) in text
    assert str(runtime.base_dir / "clean.qcow2") not in text
    for prohibited in ("hostfwd", "spice", "webdav", "usb-redir", "passthru", "vfio", "virtfs", "fsdev"):
        assert prohibited not in text
    assert "org.qemu.guest_agent.0" in text
    assert "OVMF_CODE_4M.fd,readonly=on" in text


def test_bwrap_mounts_no_home_app_tokens_or_samples(runtime):
    command = namespace.bwrap_command(runtime.run_dir, runtime.base_dir, runtime.uuid, runtime.qemu_command())
    assert command[0] == "/usr/bin/bwrap"
    assert "--unshare-all" in command and "--die-with-parent" in command
    assert "--clearenv" in command
    mounts = []
    for index, arg in enumerate(command):
        if arg in ("--bind", "--ro-bind", "--dev-bind"):
            mounts.append((arg, command[index + 1], command[index + 2]))
    assert ("--bind", str(runtime.run_dir.resolve()), str(runtime.run_dir.resolve())) in mounts
    assert ("--ro-bind", str(runtime.base_dir.resolve()), str(runtime.base_dir.resolve())) in mounts
    assert ("--dev-bind", "/dev/kvm", "/dev/kvm") in mounts
    assert all(src not in ("/", "/home", str(Path.home()), str(bootstrap.ROOT)) for _, src, _ in mounts)
    assert all("samples" not in src and "token" not in src for _, src, _ in mounts)


def test_operations_fail_before_isolated_start(runtime, tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"not executed")
    with pytest.raises(vm.IsolationError):
        runtime.push(sample, r"C:\Sandbox\sample.exe")
    with pytest.raises(vm.IsolationError):
        runtime.exec("Write-Output harmless")
    with pytest.raises(vm.IsolationError):
        runtime.screenshot(runtime.run_dir / "screen.png")


def test_runtime_lock_enforces_sequential_runs(runtime):
    second = vm.AnalysisVM(runtime.run_dir.parent / "run2", runtime.base_dir, {"id": "standard"})
    runtime._lock_runtime()
    try:
        with pytest.raises(vm.VMError, match="sequenziali"):
            second._lock_runtime()
    finally:
        runtime.stop()
    second._lock_runtime()
    second.stop()


def test_namespace_creation_failure_reaps_tpm_and_lock(runtime, monkeypatch):
    monkeypatch.setattr(runtime, "_check_paths", lambda: None)
    monkeypatch.setattr(vm.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=0))
    # qemu-img fixture creates only the disposable overlay.
    original_run = vm.subprocess.run
    def image_create(*args, **kwargs):
        runtime.overlay.write_bytes(b"overlay")
        return original_run(*args, **kwargs)
    monkeypatch.setattr(vm.subprocess, "run", image_create)
    tpm = Mock(pid=456)
    tpm.poll.return_value = None
    failed_namespace = Mock(pid=457)
    failed_namespace.poll.return_value = 1
    def launch(command, name):
        if name == "tpm.log":
            runtime.tpm_socket.touch()
            return tpm
        return failed_namespace
    monkeypatch.setattr(runtime, "_launch", launch)
    killed = []
    monkeypatch.setattr(runtime, "_kill_group", lambda proc: killed.append(proc))
    with pytest.raises(vm.IsolationError):
        runtime.start()
    assert tpm in killed and failed_namespace in killed
    assert runtime._lock is None
    assert not runtime._isolation_confirmed
    assert (runtime.base_dir / "clean.qcow2").read_bytes() == b"clean-fixture"


def test_pull_excess_bytes_removes_partial_artifact(runtime, monkeypatch):
    monkeypatch.setattr(runtime, "_assert_isolated", lambda: None)
    def agent(command, arguments=None, timeout=15):
        if command == "guest-file-open":
            return 1
        if command == "guest-file-read":
            return {"count": 4, "buf-b64": base64.b64encode(b"1234").decode(), "eof": True}
        return {}
    monkeypatch.setattr(runtime, "_agent", agent)
    target = runtime.run_dir / "artifacts/out.bin"
    with pytest.raises(vm.VMError, match="limite"):
        runtime.pull(r"C:\Sandbox\out.bin", target, max_bytes=3)
    assert not target.exists()
    assert not list(target.parent.glob("*.part-*"))


def test_pull_rejects_artifact_path_outside_run(runtime, monkeypatch):
    monkeypatch.setattr(runtime, "_assert_isolated", lambda: None)
    with pytest.raises(vm.VMError, match="fuori"):
        runtime.pull(r"C:\Sandbox\out.bin", runtime.run_dir.parent / "outside")


def test_push_checks_guest_file_write_count(runtime, monkeypatch, tmp_path):
    monkeypatch.setattr(runtime, "_assert_isolated", lambda: None)
    # Transfer accounting is independent from the new privacy preflight (covered separately).
    monkeypatch.setattr(runtime, "_assert_privacy", lambda: None)
    file = tmp_path / "file.bin"
    file.write_bytes(b"bounded")
    calls = []
    def agent(command, arguments=None, timeout=15):
        calls.append(command)
        if command == "guest-file-open":
            return 1
        return {"count": 0}
    monkeypatch.setattr(runtime, "_agent", agent)
    with pytest.raises(vm.VMError, match="parziale"):
        runtime.push(file, r"C:\Sandbox\sample.bin")
    assert calls[-1] == "guest-file-close"


def test_power_shell_is_encoded_and_rpc_timeout_stops_vm(runtime, monkeypatch):
    monkeypatch.setattr(runtime, "_assert_isolated", lambda: None)
    stopped = Mock()
    monkeypatch.setattr(runtime, "stop", stopped)
    captured = []
    def agent(command, arguments=None, timeout=15):
        captured.append((command, arguments))
        if command == "guest-exec":
            return {"pid": 99}
        raise TimeoutError("delayed guest")
    monkeypatch.setattr(runtime, "_agent", agent)
    script = "Write-Output 'safe ; $(not host-shell)'"
    with pytest.raises(TimeoutError):
        runtime.exec(script)
    args = captured[0][1]["arg"]
    assert "-EncodedCommand" in args
    assert base64.b64decode(args[-1]).decode("utf-16le") == script
    stopped.assert_called_once()


def test_cleanup_preserves_evidence_and_destroys_disposable_state(runtime, monkeypatch):
    runtime.private.mkdir(parents=True)
    runtime.overlay.write_bytes(b"dirty")
    evidence = runtime.run_dir / "network.pcap"
    evidence.write_bytes(b"evidence")
    monkeypatch.setattr(runtime, "_kill_group", lambda proc: None)
    runtime.cleanup()
    assert evidence.read_bytes() == b"evidence"
    assert not runtime.private.exists()
    assert (runtime.base_dir / "tpm2-00.permall").read_bytes() == b"clean-fixture"


def test_kill_group_reaps_helpers_even_if_leader_already_exited(monkeypatch):
    proc = Mock(pid=345)
    proc.wait.return_value = 0
    killed = []
    monkeypatch.setattr(vm.os, "killpg", lambda pid, sig: killed.append((pid, sig)))
    vm.AnalysisVM._kill_group(proc)
    assert killed == [(345, vm.signal.SIGTERM), (345, vm.signal.SIGKILL)]
    proc.wait.assert_called_once_with(timeout=5)


def test_snapshot_extraction_uses_copy_and_matching_sidecars(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    for name in ("disk.qcow2", *bootstrap.SIDECARS):
        (source / name).write_bytes(b"original-" + name.encode())
    snapshots = tmp_path / "snapshots"
    side = snapshots / "clean-base"
    side.mkdir(parents=True)
    for name in bootstrap.SIDECARS:
        (side / name).write_bytes(b"snapshot-" + name.encode())
    base = tmp_path / "bases"
    calls = []
    monkeypatch.setattr(bootstrap, "assert_source_off", lambda source: None)
    def run(command, timeout=1800):
        calls.append(command)
        if command[:2] == ["qemu-img", "info"]:
            return json.dumps({"format": "qcow2", "snapshots": [{"name": "clean-base"}]}).encode()
        if command[0] == "cp":
            shutil.copyfile(command[-2], command[-1])
        if command[:2] == ["qemu-img", "convert"]:
            Path(command[-1]).write_bytes(b"flattened-snapshot")
        return b""
    monkeypatch.setattr(bootstrap, "_run", run)
    before = bootstrap._source_signature(source)
    result = bootstrap.extract(source, base, "clean-base", snapshots)
    stage = Path(result["stage"])
    assert result["status"] == "extracted"
    assert bootstrap._source_signature(source) == before
    convert = next(command for command in calls if command[:2] == ["qemu-img", "convert"])
    assert convert[2:4] == ["-l", "snapshot.name=clean-base"]
    assert Path(convert[-2]).parent == stage
    assert Path(convert[-2]) != source / "disk.qcow2"
    assert (stage / "OVMF_VARS.fd").read_bytes() == b"snapshot-OVMF_VARS.fd"
    assert not (base / "clean.qcow2").exists()
    assert json.loads((stage / "metadata.json").read_text())["ready"] is False
    assert bootstrap.extract(source, base, "clean-base", snapshots)["status"] == "already_extracted"


def test_provision_requires_clean_shutdown_before_promotion(tmp_path, monkeypatch):
    base = tmp_path / "bases"
    stage = bootstrap._stage(base)
    stage.mkdir()
    (stage / "metadata.json").write_text(json.dumps({"ready": False}))
    guest = tmp_path / "guest"
    guest.mkdir()
    for name in bootstrap.REQUIRED_GUEST:
        (guest / name).write_text("fixture")
    shutil.copyfile(bootstrap.ROOT / "guest/privacy.ps1", guest / "privacy.ps1")
    cleaned = []
    class FakeVM:
        def __init__(self, run_dir, base_dir, profile):
            self.run_dir = run_dir
            self.run_dir.mkdir(parents=True)
        def start(self):
            pass
        def wait_agent(self, timeout):
            return True
        def exec(self, script, timeout):
            return 0, "", ""
        def pull(self, src, dst, max_bytes):
            from test_runtime_status import valid_proof
            dst.write_text(json.dumps({"ready": True, "capabilities": {}, "privacy": valid_proof()}))
        def shutdown(self, timeout):
            return False
        def cleanup(self):
            cleaned.append(True)
    monkeypatch.setattr(bootstrap, "AnalysisVM", FakeVM)
    monkeypatch.setattr(bootstrap, "_upload_guest", lambda *a: False)
    monkeypatch.setattr(bootstrap, "_verify_network", lambda *a: {"host": True, "lan": True, "internet": True, "synthetic_http": True})
    with pytest.raises(vm.VMError, match="non pulito"):
        bootstrap.provision(base, guest, tmp_path / "tools")
    assert not (base / "clean.qcow2").exists()
    assert cleaned == [True]


def test_unknown_base_never_reports_ready(tmp_path):
    result = vm.capabilities(tmp_path / "missing")
    assert result["available"] is False
    assert result["base_ready"] is False
    assert result["isolation"]["confirmed"] is False


def test_artifact_limit_can_exceed_sample_limit_but_is_bounded(runtime, monkeypatch):
    monkeypatch.setattr(runtime, "_assert_isolated", lambda: None)
    monkeypatch.setattr(vm, "CHUNK_BYTES", 600 * 1024 * 1024)
    requested = []
    def agent(command, arguments=None, timeout=15):
        if command == "guest-file-open":
            return 1
        if command == "guest-file-read":
            requested.append(arguments["count"])
            return {"count": 0, "buf-b64": "", "eof": True}
        return {}
    monkeypatch.setattr(runtime, "_agent", agent)
    runtime.pull(r"C:\Sandbox\out.pml", runtime.run_dir / "out.pml", max_bytes=999 * 1024 * 1024)
    assert requested == [512 * 1024 * 1024 + 1]
    assert vm.MAX_FILE_BYTES == 100 * 1024 * 1024


@pytest.mark.parametrize("shutdown", [False, True])
def test_qga_sync_discards_stale_partial_bytes_and_shutdown_is_one_way(runtime, monkeypatch, shutdown):
    monkeypatch.setattr(runtime, "_assert_isolated", lambda: None)
    monkeypatch.setattr(vm.os, "urandom", lambda count: b"\x00\x00\x00\x07")
    chunks = [b'partial stale response without closing brace', b'\xff{"return":7}\n']
    if not shutdown:
        chunks.append(b'{"return":{"ok":true}}\n')
    sent = []
    class FakeSocket:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def settimeout(self, timeout):
            pass
        def connect(self, path):
            pass
        def sendall(self, payload):
            sent.append(payload)
        def recv(self, count):
            assert chunks, "guest-shutdown must not wait for a nonexistent response"
            return chunks.pop(0)
    monkeypatch.setattr(vm.socket, "socket", lambda *a: FakeSocket())
    command = "guest-shutdown" if shutdown else "guest-ping"
    result = runtime._agent(command)
    assert result is None if shutdown else result == {"ok": True}
    assert not chunks
    assert json.loads(sent[-1])["execute"] == command


def test_runtime_rejects_symlinked_ancestors_before_launch(runtime, tmp_path):
    link = tmp_path / "alias"
    link.symlink_to(tmp_path, target_is_directory=True)
    instance = vm.AnalysisVM(link / "new-run", runtime.base_dir, {"id": "standard"})
    with pytest.raises(vm.VMError, match="canonica"):
        instance._check_paths()


def test_maintenance_media_is_opt_in_read_only_and_rejects_symlinks(runtime):
    assert "media=cdrom" not in " ".join(runtime.qemu_command())
    runtime.profile["_maintenance_media"] = True
    with pytest.raises(vm.VMError, match="Media offline"):
        runtime.qemu_command()
    runtime.run_dir.mkdir()
    media = runtime.run_dir / "maintenance.iso"
    media.write_bytes(b"trusted-offline-fixture")
    assert f"media=cdrom,format=raw,readonly=on,file={media}" in " ".join(runtime.qemu_command())
    media.unlink()
    media.symlink_to(runtime.base_dir / "clean.qcow2")
    with pytest.raises(vm.VMError, match="Media offline"):
        runtime.qemu_command()


def test_exec_rpc_budget_survives_busy_guest_but_keeps_overall_deadline(runtime, monkeypatch):
    monkeypatch.setattr(runtime, "_assert_isolated", lambda: None)
    observed = []
    def rpc(command, arguments, timeout):
        observed.append(timeout)
        if command == "guest-exec":
            return {"pid": 42}
        return {"exited": True, "exitcode": 0, "out-data": "", "err-data": ""}
    monkeypatch.setattr(runtime, "_agent", rpc)
    assert runtime.exec("Write-Output benign", timeout=100) == (0, "", "")
    assert len(observed) == 2
    assert all(15 < timeout <= 120 for timeout in observed)


def test_qga_ready_is_not_enough_wait_for_actual_interactive_shell(runtime, monkeypatch):
    answers = iter([(0, "False\r\n", ""), (0, "True\r\n", "")])
    scripts = []
    def execute(script, timeout):
        scripts.append(script)
        return next(answers)
    monkeypatch.setattr(runtime, "exec", execute)
    monkeypatch.setattr(vm.time, "sleep", lambda _: None)
    assert runtime.wait_desktop(30) is True
    assert len(scripts) == 2
    assert "-IncludeUserName" in scripts[0] and "Quickemu" in scripts[0]


def test_desktop_gate_fails_closed_after_rpc_failure(runtime, monkeypatch):
    def stalled(*args, **kwargs):
        raise TimeoutError("stalled before desktop")
    monkeypatch.setattr(runtime, "exec", stalled)
    assert runtime.wait_desktop(30) is False


def test_desktop_uses_full_finite_readiness_budget(runtime, monkeypatch):
    budgets = []
    monkeypatch.setattr(runtime, "exec", lambda script, timeout: (budgets.append(timeout) or (0, "True", "")))
    assert runtime.wait_desktop(180) is True
    assert len(budgets) == 1 and 120 < budgets[0] <= 180


def test_rpc_under_load_keeps_hard_120_second_cap(runtime, monkeypatch):
    monkeypatch.setattr(runtime, "_assert_isolated", lambda: None)
    budgets = []
    def rpc(command, arguments, timeout):
        budgets.append(timeout)
        return {"pid": 42} if command == "guest-exec" else {"exited": True, "exitcode": 0}
    monkeypatch.setattr(runtime, "_agent", rpc)
    assert runtime.exec("Write-Output benign", timeout=500) == (0, "", "")
    assert budgets == [120, 120]


def test_internet_mode_is_explicit_default_remains_offline(runtime):
    assert runtime.network_mode == "offline"
    assert "restrict=on,ipv6=off" in " ".join(runtime.qemu_command())
    runtime.profile["network"] = "internet"
    text = " ".join(runtime.qemu_command())
    assert runtime.network_mode == "internet"
    assert "restrict=off,ipv6=off" in text
    assert "guestfwd=tcp:10.0.2.100:80-cmd:" in text
    assert "hostfwd" not in text and "OVMF_CODE_4M.fd,readonly=on" in text


@pytest.mark.parametrize("flag", ["_provisioning", "_maintenance", "_maintenance_media"])
def test_maintenance_and_provisioning_force_offline_even_with_internet_profile(runtime, flag):
    runtime.profile.update(network="internet")
    runtime.profile[flag] = True
    if flag == "_maintenance_media":
        runtime.run_dir.mkdir()
        (runtime.run_dir / "maintenance.iso").write_bytes(b"offline-media")
    assert runtime.network_mode == "offline"
    assert "restrict=on,ipv6=off" in " ".join(runtime.qemu_command())


def test_unknown_network_mode_has_no_permissive_fallback(runtime):
    runtime.profile["network"] = "unrestricted"
    with pytest.raises(vm.VMError, match="sconosciuta"):
        runtime.qemu_command()


def _internet_proof(runtime):
    from lab import egress
    policy = egress.policy_from_snapshot(
        [{"ifname": "eth0", "addr_info": [{"family": "inet", "local": "192.168.3.2", "prefixlen": 24}]}],
        [{"dst": "default", "dev": "eth0", "gateway": "192.168.3.1"}], [], runtime.uuid)
    final = egress.with_public_identity(policy, "8.8.4.4")
    gateway = {"ready": True, "nonce": runtime.uuid, "base_policy_sha256": egress.digest(policy),
               "net_namespace": "net:[isolated]", "user_namespace": "user:[isolated]",
               "sandbox": True, "seccomp": True, "disable_host_loopback": True, "disable_dns": True}
    proof = {
        "nonce": runtime.uuid, "confirmed": True, "qemu_started": True, "qemu_argv_sha256": "expected-hash",
        "host_net_namespace": os.readlink("/proc/self/ns/net"), "host_user_namespace": os.readlink("/proc/self/ns/user"),
        "net_namespace": "net:[isolated]", "user_namespace": "user:[isolated]",
        "capabilities_dropped": True, "no_new_privs": True,
        "capability_status": {**{name: "0000000000000000" for name in ("CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb")},
                              "NoNewPrivs": "1"},
        "network_mode": "internet", "guest_internet": True, "guest_lan": False, "guest_host": False,
        "slirp_restrict": False, "interfaces": ["lo", "tap0"], "gateway": gateway,
        "base_policy_sha256": egress.digest(policy), "policy_sha256": egress.digest(final),
        "public_identity": final["public_identity"], "public_identity_state": "confirmed-and-blocked",
        "firewall": egress.verify_ruleset({"nftables": egress.ruleset_objects(final)}, final),
        "resolvers": list(egress.RESOLVERS), "outer_address": egress.OUTER_ADDRESS, "outer_gateway": egress.OUTER_GATEWAY,
    }
    controller = Mock(spec=egress.EgressGateway, policy=policy,
                      namespaces={"net_namespace": "net:[isolated]", "user_namespace": "user:[isolated]",
                                  "gateway_evidence": gateway})
    return proof, controller


def test_verified_internet_start_proof_keeps_nonce_hash_namespace_and_capability_guards(runtime):
    runtime.profile["network"] = "internet"
    proof, runtime.egress = _internet_proof(runtime)
    assert runtime._validate_start_proof(proof, "expected-hash")
    for field, invalid in (("nonce", "other-run"), ("qemu_argv_sha256", "other-command"),
                           ("net_namespace", os.readlink("/proc/self/ns/net")),
                           ("user_namespace", os.readlink("/proc/self/ns/user")),
                           ("capabilities_dropped", False), ("no_new_privs", False)):
        broken = {**proof, field: invalid}
        assert not runtime._validate_start_proof(broken, "expected-hash")
    proof["capability_status"]["CapEff"] = "1000"
    assert not runtime._validate_start_proof(proof, "expected-hash")


def test_internet_start_proof_denied_without_actual_verified_firewall(runtime):
    runtime.profile["network"] = "internet"
    proof, runtime.egress = _internet_proof(runtime)
    proof["firewall"] = {"verified": True, "sha256": "fabricated", "ruleset": {"nftables": []}}
    assert not runtime._validate_start_proof(proof, "expected-hash")


def test_internet_start_proof_denied_if_controller_missing_or_gateway_dead(runtime):
    runtime.profile["network"] = "internet"
    proof, controller = _internet_proof(runtime)
    assert not runtime._validate_start_proof(proof, "expected-hash")
    runtime.egress = controller
    from lab.egress import EgressError
    controller.assert_live.side_effect = EgressError("gateway died")
    assert not runtime._validate_start_proof(proof, "expected-hash")


def test_unverified_firewall_start_reaps_gateway_tpm_and_never_allows_sample_transfer(runtime, monkeypatch, tmp_path):
    import hashlib
    runtime.profile["network"] = "internet"
    proof, controller = _internet_proof(runtime)
    proof["firewall"] = {"verified": False, "ruleset": {"nftables": []}}
    monkeypatch.setattr(runtime, "_check_paths", lambda: None)
    def image_create(*args, **kwargs):
        runtime.overlay.write_bytes(b"disposable-overlay")
    monkeypatch.setattr(vm.subprocess, "run", image_create)
    tpm = Mock()
    tpm.poll.return_value = None
    qemu = Mock()
    qemu.poll.return_value = None
    def launch(command, name):
        assert name == "tpm.log"
        runtime.tpm_socket.touch()
        return tpm
    monkeypatch.setattr(runtime, "_launch", launch)
    def start_gateway(launcher):
        proof["qemu_argv_sha256"] = hashlib.sha256(json.dumps(runtime.qemu_command()).encode()).hexdigest()
        (runtime.run_dir / "namespace.json").write_text(json.dumps(proof))
        return qemu
    controller.start.side_effect = start_gateway
    monkeypatch.setattr(vm, "EgressGateway", lambda *a: controller)
    killed = []
    monkeypatch.setattr(runtime, "_kill_group", lambda process: killed.append(process))
    with pytest.raises(vm.IsolationError, match="incompleta"):
        runtime.start()
    controller.close.assert_called_once()
    assert qemu in killed and tpm in killed
    assert runtime._lock is None and not runtime._isolation_confirmed
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"never-transferred")
    with pytest.raises(vm.IsolationError):
        runtime.push(sample, r"C:\Sandbox\sample.bin")


def test_gateway_death_blocks_guest_rpc_and_stops_private_runtime(runtime, monkeypatch):
    from lab.egress import EgressError
    runtime.profile["network"] = "internet"
    runtime._isolation_confirmed = True
    runtime.proc = Mock()
    runtime.proc.poll.return_value = None
    runtime.tpm_proc = Mock()
    runtime.tpm_proc.poll.return_value = None
    runtime.egress = Mock(spec=vm.EgressGateway)
    runtime.egress.assert_live.side_effect = EgressError("gateway dead")
    monkeypatch.setattr(runtime, "_kill_group", Mock())
    with pytest.raises(vm.IsolationError, match="gateway dead"):
        runtime._assert_isolated()
    assert runtime._closed and not runtime._isolation_confirmed
    runtime.egress.close.assert_called_once()


def test_gateway_cleanup_failure_still_reaps_tpm_and_releases_lock(runtime, monkeypatch):
    runtime._lock_runtime()
    runtime.proc, runtime.tpm_proc = Mock(), Mock()
    tpm = runtime.tpm_proc
    runtime.egress = Mock()
    runtime.egress.close.side_effect = RuntimeError("gateway cleanup failed")
    killed = []
    monkeypatch.setattr(runtime, "_kill_group", lambda process: killed.append(process))
    with pytest.raises(RuntimeError, match="gateway cleanup failed"):
        runtime.stop()
    assert tpm in killed and runtime._lock is None
    assert runtime._closed and runtime.proc is None and runtime.tpm_proc is None


def test_runner_never_executes_unrestricted_qemu_without_verified_internet_policy(tmp_path, monkeypatch):
    monkeypatch.setattr(namespace, "namespace_evidence", lambda *a: {"confirmed": True, "network_mode": "offline"})
    monkeypatch.setattr(namespace, "drop_capabilities", lambda: {"capabilities_dropped": True, "no_new_privs": True})
    monkeypatch.setattr(namespace.os, "umask", Mock())
    popen = Mock()
    monkeypatch.setattr(namespace.subprocess, "Popen", popen)
    result = namespace.main(["--run-dir", str(tmp_path), "--nonce", "offline-only", "--host-net", "hostnet",
                             "--host-user", "hostuser", "--", "/usr/bin/qemu-system-x86_64",
                             "-netdev", "user,id=nic,restrict=off,ipv6=off"])
    assert result == 1
    popen.assert_not_called()
    proof = json.loads((tmp_path / "namespace.json").read_text())
    assert proof["qemu_started"] is False and proof["confirmed"] is False
    assert "policy" in proof["error"]


def test_internet_prerequisite_uses_pinned_nft_without_service_sbin_path(runtime, monkeypatch):
    requested = []
    def lookup(command):
        requested.append(command)
        return None if command == "nft" else command
    monkeypatch.setattr(vm.shutil, "which", lookup)
    monkeypatch.setattr(vm.os, "access", lambda *args: True)
    runtime.profile["network"] = "internet"
    runtime._check_paths()
    assert "/usr/sbin/nft" in requested and "nft" not in requested
    assert vm.capabilities(runtime.base_dir)["network"]["internet_prerequisites"]["nft"]

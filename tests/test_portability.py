import contextlib
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from lab import bootstrap, config, vm
from test_runtime_status import valid_proof


@pytest.mark.parametrize("phase", ["extract", "all"])
@pytest.mark.parametrize("provided", [[], ["--source", "/unused/source"], ["--snapshots-dir", "/unused/snapshots"]])
def test_extract_cli_requires_explicit_inputs_before_mutation(tmp_path, monkeypatch, phase, provided):
    base = tmp_path / "new-parent" / "bases"
    monkeypatch.setattr(bootstrap, "bootstrap_lock", lambda *args: pytest.fail("must reject before lock/write"))
    monkeypatch.setattr(bootstrap.os, "umask", lambda *args: pytest.fail("must reject before umask"))
    with pytest.raises(SystemExit) as error:
        bootstrap.main([phase, "--base-dir", str(base), *provided])
    assert error.value.code == 2
    assert not base.parent.exists()


def test_provision_cli_needs_no_source(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(bootstrap, "bootstrap_lock", lambda *args: contextlib.nullcontext())
    monkeypatch.setattr(bootstrap.os, "umask", lambda *args: None)
    monkeypatch.setattr(bootstrap, "provision", lambda *args, **kwargs: calls.append((args, kwargs)) or {"status": "ready"})
    assert bootstrap.main(["provision", "--base-dir", str(tmp_path / "bases")]) == 0
    assert calls[0][0][0] == tmp_path / "bases"


def test_extract_cli_generic_snapshot_default(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(bootstrap, "bootstrap_lock", lambda *args: contextlib.nullcontext())
    monkeypatch.setattr(bootstrap.os, "umask", lambda *args: None)
    monkeypatch.setattr(bootstrap, "extract", lambda *args: calls.append(args) or {})
    assert bootstrap.main(["extract", "--source", str(tmp_path / "source"),
                           "--snapshots-dir", str(tmp_path / "snapshots")]) == 0
    assert calls[0][2] == "clean-base"


def test_public_profiles_default_offline_and_internet_requires_explicit_choice():
    assert all(profile["network"] == "offline" for profile in config.profiles_for_network())
    assert all(profile["network"] == "internet" for profile in config.profiles_for_network("internet"))
    with pytest.raises(ValueError, match="no permissive fallback"):
        config.profiles_for_network("unrestricted")
    assert all("network" not in profile for profile in config.PROFILE_DEFINITIONS)


def test_vnc_lookup_uses_only_interpreter_sibling_and_path(monkeypatch):
    seen = []
    monkeypatch.setattr(vm.sys, "executable", "/opt/blacksite/bin/python")
    monkeypatch.setattr(vm.shutil, "which", lambda name: "/usr/local/bin/vncdo")
    monkeypatch.setattr(vm.os, "access", lambda path, flags: seen.append(path) or path == "/usr/local/bin/vncdo")
    assert vm._vnc_binary() == "/usr/local/bin/vncdo"
    assert seen == ["/opt/blacksite/bin/vncdo", "/usr/local/bin/vncdo"]


def test_custom_privacy_enforcer_is_rejected_before_vm_launch(tmp_path, monkeypatch):
    base = tmp_path / "bases"
    stage = bootstrap._stage(base)
    stage.mkdir()
    (stage / "metadata.json").write_text('{"ready":false}')
    guest = tmp_path / "guest"
    guest.mkdir()
    for name in bootstrap.REQUIRED_GUEST:
        (guest / name).write_text("untrusted fixture")
    monkeypatch.setattr(bootstrap, "AnalysisVM", lambda *args: pytest.fail("must reject before launch"))
    with pytest.raises(vm.VMError, match="privacy fidato"):
        bootstrap.provision(base, guest, tmp_path / "tools")
    assert not (tmp_path / "bootstrap-runs").exists()


@pytest.mark.parametrize("missing", ["kernel_trace.ps1", *bootstrap.KERNEL_ASSETS])
def test_required_kernel_input_missing_rejects_before_vm_launch(tmp_path, monkeypatch, missing):
    base = tmp_path / "bases"
    stage = bootstrap._stage(base)
    stage.mkdir()
    (stage / "metadata.json").write_text('{"ready":false}')
    guest = tmp_path / "guest"
    guest.mkdir()
    for name in bootstrap.REQUIRED_GUEST:
        if name != missing:
            (guest / name).write_bytes((bootstrap.ROOT / "guest" / name).read_bytes())
    monkeypatch.setattr(bootstrap, "AnalysisVM", lambda *args: pytest.fail("must reject before launch"))
    with pytest.raises(vm.VMError, match=missing.replace(".", r"\.")):
        bootstrap.provision(base, guest, tmp_path / "tools")
    assert not (tmp_path / "bootstrap-runs").exists()


def test_upload_does_not_replace_preverified_pinned_enforcer(tmp_path):
    guest = tmp_path / "guest"
    guest.mkdir()
    for name in bootstrap.REQUIRED_GUEST:
        source = bootstrap.ROOT / "guest" / name
        (guest / name).write_bytes(source.read_bytes())
    (guest / "PRIVACY.PS1").write_text("case-insensitive override")
    (guest / "untrusted.cs").write_text("not a collector asset")
    (guest / "untrusted.wprp").write_text("not a collector asset")
    instance = Mock()
    instance.exec.return_value = (0, "", "")
    assert bootstrap._upload_guest(instance, guest, tmp_path / "tools", False) is False
    names = [call.args[0].name.lower() for call in instance.push.call_args_list]
    assert "privacy.ps1" not in names
    assert "baseline.ps1" in names and "setup.ps1" in names
    assert "kernel_trace.ps1" in names
    assert all(name in names for name in bootstrap.KERNEL_ASSETS)
    assert "untrusted.cs" not in names and "untrusted.wprp" not in names


@pytest.mark.parametrize("privacy_valid", [True, False])
def test_fresh_provision_publishes_only_validated_privacy_and_offline_profiles(tmp_path, monkeypatch, privacy_valid):
    base = tmp_path / "bases"
    stage = bootstrap._stage(base)
    stage.mkdir()
    (stage / "metadata.json").write_text('{"ready":false,"phase":"extracted"}')
    order = []
    proof = valid_proof() if privacy_valid else {}

    class FreshVM:
        def __init__(self, run_dir, base_dir, profile):
            assert profile["_provisioning"] is True
            self.run_dir = run_dir
            self.run_dir.mkdir()
            self.uuid = "b" * 32
            self.private = run_dir / "v"
            (self.private / "tpm").mkdir(parents=True)
            for name in ("OVMF_VARS.fd", "tpm/tpm2-00.permall"):
                (self.private / name).write_bytes(b"private-state")
            self.overlay = self.private / "overlay.qcow2"
            self.overlay.write_bytes(b"private-overlay")
            self.isolation = {"confirmed": True, "guest_internet": False}
            self.guarded = False

        def start(self):
            # Real start() uses the sole pinned pre-privacy transfer, then validates.
            order.append("pinned_privacy_verified")
            self.guarded = True

        def wait_agent(self, timeout):
            return True

        def exec(self, script, timeout=180):
            if "setup.ps1" in script:
                assert "setup.ps1" in order and "baseline.ps1" in order
                assert "kernel_trace.ps1" in order
                assert all(name in order for name in bootstrap.KERNEL_ASSETS)
                order.append("setup")
            return 0, "", ""

        def push(self, source, destination):
            assert self.guarded
            assert source.name.lower() != "privacy.ps1"
            order.append(source.name)

        def pull(self, source, destination, max_bytes):
            destination.write_text(json.dumps({"ready": True, "capabilities": {"sysmon": {"status": "available"}}, "privacy": proof}))

        def shutdown(self, timeout):
            order.append("clean_shutdown")
            return True

        def cleanup(self):
            order.append("cleanup")

    def run(command, timeout=1800):
        if command[:2] == ["qemu-img", "convert"]:
            Path(command[-1]).write_bytes(b"flattened")
            return b""
        assert command[:2] == ["qemu-img", "info"]
        return b'{"format":"qcow2"}'

    monkeypatch.setattr(bootstrap, "AnalysisVM", FreshVM)
    monkeypatch.setattr(bootstrap, "_verify_network", lambda instance: {"host": True, "lan": True, "internet": True, "synthetic_http": True})
    monkeypatch.setattr(bootstrap, "_run", run)
    monkeypatch.setattr(bootstrap, "PROFILES", config.profiles_for_network())
    if not privacy_valid:
        with pytest.raises(vm.VMError, match="Privacy guest"):
            bootstrap.provision(base, bootstrap.ROOT / "guest", tmp_path / "tools", install_frida=False)
        assert not (base / "clean.qcow2").exists()
        assert "clean_shutdown" not in order
    else:
        result = bootstrap.provision(base, bootstrap.ROOT / "guest", tmp_path / "tools", install_frida=False)
        metadata = json.loads((base / "metadata.json").read_text())
        assert result["status"] == "ready"
        assert metadata["privacy"] == proof
        assert all(profile["network"] == "offline" for profile in result["profiles"])
        assert order.index("setup") < order.index("clean_shutdown")
    assert order[0] == "pinned_privacy_verified"
    assert order[-1] == "cleanup"

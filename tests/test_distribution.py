"""Pure rendering and mocked integration tests: never contact systemd or a VM."""
import importlib.util
from pathlib import Path
import shlex
from types import SimpleNamespace

import pytest

from scripts import install_desktop as installer
from scripts import launcher


def checkout(tmp_path):
    root = tmp_path / 'BLACK SITE [1]*? % $ " \\ `'
    for relative in (".venv/bin/python", "lab/api.py", "scripts/launcher.py"):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
    (root / ".venv/bin/python").chmod(0o700)
    (root / ".env.example").write_text("BLACKSITE_NETWORK=offline\nVT_API_KEY=\n", encoding="utf-8")
    return root


def test_unit_quotes_paths_and_uses_venv(tmp_path):
    root = checkout(tmp_path)
    unit = installer.render_unit(root)
    fields = dict(line.split("=", 1) for line in unit.splitlines() if "=" in line)
    assert fields["WorkingDirectory"].replace("%%", "%") == str(root) + "/."
    command = shlex.split(fields["ExecStart"])
    assert command[0] == ":/usr/bin/env"
    assert command[1].replace("%%", "%") == str(root / ".venv/bin/python")
    assert command[2:] == ["-m", "uvicorn", "lab.api:app", "--host", "127.0.0.1", "--port", "8765"]
    expected_env = "-" + installer.environment_path(tmp_path) + r'/BLACK SITE \[1\]\*\? %% $ " \\ `/data/integrations.env'
    assert fields["EnvironmentFile"] == expected_env
    assert fields["Environment"] == "BLACKSITE_NETWORK=offline"
    assert fields["UMask"] == "0077"
    assert fields["Restart"] == "no"


def test_working_directory_trailing_backslash_cannot_continue_unit_line():
    root = Path("/tmp/BLACK SITE\\")
    unit = installer.render_unit(root)
    assert f"WorkingDirectory={root}/.\nEnvironment=" in unit


def test_desktop_quotes_both_decoding_layers():
    encoded = installer.desktop_quote(Path('/tmp/BLACK SITE % $ " \\ `'))
    assert encoded == '"/tmp/BLACK SITE %% ' + "\\\\$ " + '\\\\" ' + "\\\\\\\\ " + "\\\\`" + '"'


def test_desktop_actions_are_explicit(tmp_path):
    root = checkout(tmp_path)
    desktop = installer.render_desktop(root)
    command = f"/usr/bin/env {installer.desktop_quote(root / '.venv/bin/python')} {installer.desktop_quote(root / 'scripts/launcher.py')}"
    assert f"Exec={command} open\n" in desktop
    assert f"Exec={command} stop\n" in desktop
    assert "Actions=Stop;" in desktop
    assert "Terminal=false" in desktop
    assert "systemctl" not in desktop


@pytest.mark.parametrize("path", [Path("relative checkout"), Path("/tmp/bad\npath"), Path("/tmp/bad\tpath"), Path("/tmp/trailing "), Path("/tmp/name=1")])
def test_invalid_paths_rejected(path):
    with pytest.raises(ValueError, match="absolute.*control"):
        installer.render_unit(path)
    with pytest.raises(ValueError, match="absolute.*control"):
        installer.desktop_quote(path)


def test_missing_or_nonexecutable_python_refused(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(installer.subprocess, "run", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(ValueError, match="Missing executable"):
        installer.install(tmp_path)
    root = checkout(tmp_path)
    (root / ".venv/bin/python").chmod(0o600)
    with pytest.raises(ValueError, match="Missing executable"):
        installer.install(root)
    assert calls == []


def test_install_is_on_demand_and_only_writes_own_files(tmp_path, monkeypatch):
    root = checkout(tmp_path)
    config = tmp_path / "user config"
    local_data = tmp_path / "user data"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config))
    monkeypatch.setenv("XDG_DATA_HOME", str(local_data))
    calls = []
    monkeypatch.setattr(installer.subprocess, "run", lambda args, **kwargs: calls.append(args))
    unit, desktop = installer.install(root)
    assert unit == config / "systemd/user/blacksite.service"
    assert desktop == local_data / "applications/blacksite.desktop"
    assert unit.stat().st_mode & 0o777 == 0o600
    assert desktop.stat().st_mode & 0o777 == 0o644
    assert calls == [["systemctl", "--user", "daemon-reload"]]
    assert not (root / "data").exists()


def test_integrations_blank_private_preserved_and_enable_explicit(tmp_path, monkeypatch):
    root = checkout(tmp_path)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "local"))
    calls = []
    monkeypatch.setattr(installer.subprocess, "run", lambda args, **kwargs: calls.append(args))
    installer.install(root, integrations=True, enable=True)
    target = root / "data/integrations.env"
    assert target.read_text() == (root / ".env.example").read_text()
    assert target.stat().st_mode & 0o777 == 0o600
    assert calls == [["systemctl", "--user", "daemon-reload"], ["systemctl", "--user", "enable", "--now", "blacksite.service"]]
    target.write_text("# Locally edited configuration; no key values\n")
    installer.install(root, integrations=True)
    assert target.read_text() == "# Locally edited configuration; no key values\n"


def test_integrations_symlink_refused(tmp_path):
    root = checkout(tmp_path)
    (root / "data").mkdir()
    other = tmp_path / "untouched"
    other.write_text("original")
    (root / "data/integrations.env").symlink_to(other)
    with pytest.raises(ValueError, match="symlink"):
        installer._create_integrations(root)
    assert other.read_text() == "original"


@pytest.mark.parametrize("module", [installer, launcher])
def test_import_has_no_process_or_write_side_effects(module, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Unexpected side effect during import")
    monkeypatch.setattr(installer.subprocess, "run", forbidden)
    monkeypatch.setattr(installer.os, "open", forbidden)
    monkeypatch.setattr(Path, "write_text", forbidden)
    spec = importlib.util.spec_from_file_location("distribution_import_probe", module.__file__)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)


def test_stop_controls_only_blacksite(monkeypatch):
    calls = []
    monkeypatch.setattr(launcher.subprocess, "run", lambda args, **kwargs: calls.append(args))
    monkeypatch.setattr(launcher, "wait_for_health", lambda: pytest.fail("Stop must not check health"))
    launcher.launch("stop")
    assert calls == [["systemctl", "--user", "stop", "blacksite.service"]]


def test_open_waits_before_browser(monkeypatch):
    calls = []
    monkeypatch.setattr(launcher.subprocess, "run", lambda args, **kwargs: calls.append(args))
    monkeypatch.setattr(launcher, "wait_for_health", lambda: calls.append("healthy"))
    launcher.launch("open")
    assert calls == [["systemctl", "--user", "start", "blacksite.service"], "healthy", ["xdg-open", launcher.URL]]


def test_failed_health_never_opens_browser(monkeypatch):
    calls = []
    monkeypatch.setattr(launcher.subprocess, "run", lambda args, **kwargs: calls.append(args))
    def unhealthy():
        raise RuntimeError("unhealthy")
    monkeypatch.setattr(launcher, "wait_for_health", unhealthy)
    with pytest.raises(RuntimeError):
        launcher.launch("open")
    assert calls == [["systemctl", "--user", "start", "blacksite.service"]]


@pytest.mark.parametrize("payload", [b'{"status":"ok","service":"BLACKSITE"}', b'{"status":"ok","service":"Other"}', b'[]'])
def test_health_requires_exact_service(payload, monkeypatch):
    class Response:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def read(self, limit):
            assert limit == 4096
            return payload
    urls = []
    def open_url(url, **kwargs):
        urls.append(url)
        return Response()
    monkeypatch.setattr(launcher, "build_opener", lambda *args: SimpleNamespace(open=open_url))
    clock = iter([0, 0, 2])
    monkeypatch.setattr(launcher, "time", SimpleNamespace(monotonic=lambda: next(clock), sleep=lambda seconds: None))
    if b'"BLACKSITE"' in payload:
        launcher.wait_for_health(timeout=1)
    else:
        with pytest.raises(RuntimeError, match="did not become healthy"):
            launcher.wait_for_health(timeout=1)
    assert urls == [launcher.URL + "api/health"]

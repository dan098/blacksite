"""Install only BLACKSITE's user unit and application-menu entry, on demand."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import tempfile

UNIT = "blacksite.service"


def _path_text(path: Path) -> str:
    text = str(path)
    if (not path.is_absolute() or "=" in text or text[-1:].isspace()
            or any(ord(char) < 32 or ord(char) == 127 for char in text)):
        raise ValueError("Integration paths must be absolute, without '=' or control characters or trailing whitespace")
    return text


def systemd_path(path: Path) -> str:
    # Scalar path directives do not decode command-line quotes or C escapes.
    return _path_text(path).replace("%", "%%")


def environment_path(path: Path) -> str:
    text = systemd_path(path)
    for char in ("\\", "*", "?", "[", "]"):
        text = text.replace(char, "\\" + char)
    return text


def systemd_quote(path: Path) -> str:
    text = systemd_path(path)
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def desktop_quote(path: Path) -> str:
    # Desktop Entry string decoding precedes Exec decoding: escape both layers.
    text = _path_text(path).replace("%", "%%")
    for char in ("\\", '"', "`", "$"):
        text = text.replace(char, "\\\\" + ("\\\\" if char == "\\" else char))
    return '"' + text + '"'


def validate_root(root: Path) -> Path:
    root = root.resolve()
    _path_text(root)
    python = root / ".venv/bin/python"
    if not python.is_file() or not os.access(python, os.X_OK):
        raise ValueError("Missing executable .venv/bin/python; run uv sync --python 3.13 first")
    if not (root / "lab/api.py").is_file() or not (root / "scripts/launcher.py").is_file():
        raise ValueError("Install from a complete BLACKSITE checkout")
    return root


def render_unit(root: Path) -> str:
    return (
        "[Unit]\n"
        "Description=BLACKSITE local analysis UI\n\n"
        "[Service]\n"
        "Type=simple\n"
        f"WorkingDirectory={systemd_path(root)}/.\n"
        "Environment=BLACKSITE_NETWORK=offline\n"
        f"EnvironmentFile=-{environment_path(root / 'data/integrations.env')}\n"
        f"ExecStart=:/usr/bin/env {systemd_quote(root / '.venv/bin/python')} "
        "-m uvicorn lab.api:app --host 127.0.0.1 --port 8765\n"
        "UMask=0077\n"
        "Restart=no\n\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )


def render_desktop(root: Path) -> str:
    command = f"/usr/bin/env {desktop_quote(root / '.venv/bin/python')} {desktop_quote(root / 'scripts/launcher.py')}"
    return (
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=BLACKSITE\n"
        "Comment=Detonate. Trace. Contain.\n"
        f"Exec={command} open\n"
        "Terminal=false\n"
        "Categories=Development;Utility;\n"
        "Actions=Stop;\n\n"
        "[Desktop Action Stop]\n"
        "Name=Stop BLACKSITE\n"
        f"Exec={command} stop\n"
    )


def _write_local(path: Path, text: str, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".blacksite-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(text)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _create_integrations(root: Path) -> None:
    # Do not read or overwrite existing secrets. Exclusive creation is deliberate.
    target = root / "data/integrations.env"
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if target.is_symlink():
        raise ValueError("Refusing a symlink for the optional integration file")
    try:
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        if not target.is_file():
            raise ValueError("Optional integration path is not a regular file") from None
        target.chmod(0o600)
        return
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write((root / ".env.example").read_text(encoding="utf-8"))


def install(root: Path, *, integrations: bool = False, enable: bool = False) -> tuple[Path, Path]:
    root = validate_root(root)
    config = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    local_data = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share")
    _path_text(config)
    _path_text(local_data)
    if integrations:
        _create_integrations(root)
    unit = config / "systemd/user" / UNIT
    desktop = local_data / "applications/blacksite.desktop"
    _write_local(unit, render_unit(root), 0o600)
    _write_local(desktop, render_desktop(root), 0o644)
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
    if enable:
        subprocess.run(["systemctl", "--user", "enable", "--now", UNIT], check=True)
    return unit, desktop


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--integrations", action="store_true", help="Create blank private data/integrations.env if absent")
    parser.add_argument("--enable", action="store_true", help="Explicitly enable autostart and start BLACKSITE now")
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("Run as your desktop user, not root")
    try:
        unit, desktop = install(Path(__file__).resolve().parents[1], integrations=args.integrations, enable=args.enable)
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"BLACKSITE integration failed: {exc}\n")
    print(f"Installed {unit}\nInstalled {desktop}")
    if not args.enable:
        print("On-demand only: open BLACKSITE from your application menu.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

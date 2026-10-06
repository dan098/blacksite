from dataclasses import dataclass, field
from pathlib import Path
import json
import os
import secrets

ROOT = Path(__file__).resolve().parents[1]

PROFILE_DEFINITIONS = [
    {"id": "standard", "name": "Windows · Standard", "description": "Defender, Sysmon, Procmon e kernel ETW; rete offline salvo opt-in esplicito", "interaction": False, "trace": False, "kernel": True},
    {"id": "interactive", "name": "Windows · Interattiva", "description": "Desktop interattivo, kernel ETW, movimenti innocui e tempi reali", "interaction": True, "trace": False, "kernel": True},
    {"id": "trace", "name": "Windows · API e kernel", "description": "Syscall/stack kernel ETW e API/Nt* user-mode Frida, copertura misurata", "interaction": True, "trace": True, "kernel": True},
    {"id": "driver", "name": "Windows · Driver/BYOVD", "description": "Kernel ETW, driver caricati e servizi; nessuna installazione automatica di .sys", "interaction": False, "trace": False, "kernel": True},
]


def profiles_for_network(network: str = "offline") -> list[dict]:
    if network not in ("offline", "internet"):
        raise ValueError("BLACKSITE_NETWORK must be offline or internet; no permissive fallback")
    return [{**profile, "network": network} for profile in PROFILE_DEFINITIONS]


PROFILES = profiles_for_network(os.environ.get("BLACKSITE_NETWORK", "offline"))
PROFILE_MAP = {p["id"]: p for p in PROFILES}

@dataclass
class Settings:
    root: Path = ROOT
    data: Path = field(default_factory=lambda: Path(os.environ.get("SANDBOX_DATA", ROOT / "data")))
    max_upload: int = 100 * 1024 * 1024
    max_queue: int = 32
    token: str = field(default="", repr=False)
    public_origin: str = field(default_factory=lambda: os.environ.get("SANDBOX_PUBLIC_ORIGIN", "").rstrip("/"))

    @property
    def samples(self):
        return self.data / "samples"

    @property
    def jobs(self):
        return self.data / "jobs"

    @property
    def tools(self):
        return self.data / "tools"

    @property
    def base_dir(self):
        return self.data / "bases"

    @property
    def db_path(self):
        return self.data / "lab.sqlite3"

    def prepare(self):
        for path in (self.data, self.samples, self.jobs, self.tools, self.base_dir):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.chmod(0o700)
        token_path = self.data / "api-token"
        if not self.token:
            if token_path.exists():
                self.token = token_path.read_text().strip()
            else:
                self.token = secrets.token_urlsafe(32)
                fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as stream:
                    stream.write(self.token + "\n")
        if token_path.exists():
            token_path.chmod(0o600)
        if len(self.token) < 32:
            raise RuntimeError("API token too short; require at least 32 characters")
        if self.public_origin and not self.public_origin.startswith("https://"):
            raise RuntimeError("SANDBOX_PUBLIC_ORIGIN must use HTTPS")

    def base_status(self):
        ready = all((self.base_dir / name).is_file() for name in ("clean.qcow2", "OVMF_VARS.fd", "tpm2-00.permall"))
        metadata = {}
        metadata_path = self.base_dir / "metadata.json"
        if metadata_path.exists():
            try:
                metadata = json.loads(metadata_path.read_text())
            except (ValueError, OSError):
                pass
        return {"status": "ready" if ready and metadata.get("ready") is True else "not_ready", "metadata": metadata}

SETTINGS = Settings()

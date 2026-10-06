"""Open or stop BLACKSITE's own user service; no actions occur on import."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from urllib.error import URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener

UNIT = "blacksite.service"
URL = "http://127.0.0.1:8765/"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def wait_for_health(timeout: float = 30) -> None:
    opener = build_opener(ProxyHandler({}), NoRedirect())
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with opener.open(URL + "api/health", timeout=1) as response:
                payload = json.loads(response.read(4096))
            if isinstance(payload, dict) and payload.get("status") == "ok" and payload.get("service") == "BLACKSITE":
                return
        except (OSError, URLError, ValueError):
            pass
        time.sleep(0.25)
    raise RuntimeError("BLACKSITE did not become healthy on loopback port 8765; inspect systemctl --user status blacksite.service")


def launch(action: str) -> None:
    if action == "stop":
        subprocess.run(["systemctl", "--user", "stop", UNIT], check=True)
    elif action == "open":
        subprocess.run(["systemctl", "--user", "start", UNIT], check=True)
        wait_for_health()
        subprocess.run(["xdg-open", URL], check=True)
    else:
        raise ValueError("Expected open or stop")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("open", "stop"))
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("Run as your desktop user, not root")
    try:
        launch(args.action)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"BLACKSITE launcher failed: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

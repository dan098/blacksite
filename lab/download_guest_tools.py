"""Fetch official installers on the host; guests never download dependencies."""
import hashlib
import io
import json
import urllib.request
import zipfile
from pathlib import Path
from lab.config import SETTINGS

MAX = 200 * 1024 * 1024


def fetch(url, limit=MAX):
    if not url.startswith("https://"):
        raise ValueError("HTTPS required")
    request = urllib.request.Request(url, headers={"User-Agent": "SandboxLab-Setup/1"})
    with urllib.request.urlopen(request, timeout=90) as response:
        chunks = []
        total = 0
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > limit:
                raise ValueError("Download limit exceeded")
            chunks.append(chunk)
        return b"".join(chunks)


def main():
    SETTINGS.prepare()
    dest = SETTINGS.tools / "guest"
    wheels = dest / "frida-wheels"
    wheels.mkdir(parents=True, exist_ok=True)
    provenance = []
    if not (dest / "uv.exe").exists():
        release = json.loads(fetch("https://api.github.com/repos/astral-sh/uv/releases/latest", 4 * 1024 * 1024))
        asset = next(asset for asset in release["assets"] if asset["name"] == "uv-x86_64-pc-windows-msvc.zip")
        data = fetch(asset["browser_download_url"])
        digest = hashlib.sha256(data).hexdigest()
        published = asset.get("digest", "")
        if published.startswith("sha256:") and published[7:] != digest:
            raise ValueError("uv publisher digest mismatch")
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            member = next(name for name in archive.namelist() if name.endswith("uv.exe"))
            (dest / "uv.exe").write_bytes(archive.read(member))
        provenance.append({"tool": "uv", "version": release["tag_name"], "source": asset["browser_download_url"], "sha256": digest, "publisher_digest_verified": bool(published)})
    else:
        provenance.append({"tool": "uv", "status": "already_downloaded", "executable_sha256": hashlib.sha256((dest / "uv.exe").read_bytes()).hexdigest()})
    manifest = json.loads(fetch("https://pypi.org/pypi/frida/json", 32 * 1024 * 1024))
    asset = next(asset for asset in manifest["urls"] if asset["filename"].endswith("win_amd64.whl") and "abi3" in asset["filename"])
    data = fetch(asset["url"])
    digest = hashlib.sha256(data).hexdigest()
    if digest != asset["digests"]["sha256"]:
        raise ValueError("Frida PyPI digest mismatch")
    (wheels / asset["filename"]).write_bytes(data)
    provenance.append({"tool": "frida", "version": manifest["info"]["version"], "source": asset["url"], "sha256": digest, "publisher_digest_verified": True})
    (dest / "provenance.json").write_text(json.dumps(provenance, indent=2))
    print(json.dumps({"guest_tools": str(dest), "provenance": provenance}, indent=2))

if __name__ == "__main__":
    main()

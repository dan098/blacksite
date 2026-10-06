"""Explicit installer for trusted tools and public metadata; never handles samples."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

LOLD_URL = "https://www.loldrivers.io/api/drivers.json"
MAX_DOWNLOAD = 64 * 1024 * 1024
PACKAGES = {"static": ("pefile", "yara-python", "cryptography"), "floss": ("flare-floss",), "capa": ("flare-capa",)}
ALLOWED_HOSTS = {"pypi.org", "api.github.com", "codeload.github.com", "www.loldrivers.io", "loldrivers.io"}


class TrustedRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urlsplit(newurl)
        if target.scheme != "https" or target.hostname not in ALLOWED_HOSTS:
            raise ValueError("Redirect fuori dalle fonti ufficiali autorizzate")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url: str) -> bytes:
    target = urlsplit(url)
    if target.scheme != "https" or target.hostname not in ALLOWED_HOSTS:
        raise ValueError("Fonte non autorizzata")
    opener = build_opener(ProxyHandler({}), TrustedRedirects())
    request = Request(url, headers={"User-Agent": "SandboxLab-ToolSetup/1.0", "Accept": "application/json,application/octet-stream"})
    with opener.open(request, timeout=45) as response:
        content = response.read(MAX_DOWNLOAD + 1)
    if len(content) > MAX_DOWNLOAD:
        raise ValueError("Download oltre il limite di 64 MiB")
    return content


def save_json(path: Path, payload) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".setup-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=True, indent=2)
            stream.write("\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def install_environment(tools: Path, component: str, python: str) -> dict:
    uv = shutil.which("uv")
    if not uv:
        raise RuntimeError("uv non disponibile; nessuna installazione con pip di sistema")
    env = tools / component
    provenance = []
    requirements = []
    for package in PACKAGES[component]:
        source = "https://pypi.org/pypi/" + package + "/json"
        payload = fetch(source)
        metadata = json.loads(payload)
        if metadata["info"]["name"].lower().replace("_", "-") != package:
            raise ValueError("Nome pacchetto PyPI inatteso")
        version = metadata["info"]["version"]
        if not isinstance(version, str) or len(version) > 80 or not all(c.isalnum() or c in ".+-!" for c in version):
            raise ValueError("Versione PyPI non valida")
        requirements.append(package + "==" + version)
        provenance.append({"package": package, "version": version, "metadata_source": source, "metadata_sha256": hashlib.sha256(payload).hexdigest(), "project_urls": metadata["info"].get("project_urls", {})})
    if not (env / "bin" / "python").is_file():
        subprocess.run([uv, "venv", "--python", python, str(env)], check=True, timeout=300)
    binary_policy = [] if component == "floss" else ["--only-binary", ":all:"]
    subprocess.run([uv, "pip", "install", "--python", str(env / "bin" / "python"), *binary_policy, *requirements], check=True, timeout=900)
    os.chmod(env, 0o700)
    lock = subprocess.run([uv, "pip", "freeze", "--python", str(env / "bin" / "python")], check=True, capture_output=True, text=True, timeout=60)
    result = {"component": component, "retrieved_at": datetime.now(timezone.utc).isoformat(), "packages": provenance, "resolved_requirements": lock.stdout.splitlines(), "source_builds_allowed": component == "floss", "note": "Pacchetti fissati alla versione PyPI rilevata; build di dipendenze PyPI consentite solo per FLOSS (halo e dipendenze senza wheel). Nessuna firma di release verificata."}
    save_json(tools / (component + "-provenance.json"), result)
    return result


def install_loldrivers(tools: Path) -> dict:
    raw = fetch(LOLD_URL)
    payload = json.loads(raw)
    if not isinstance(payload, list) or len(payload) > 40000:
        raise ValueError("Formato LOLDrivers inatteso")
    records = []
    for driver in payload:
        if not isinstance(driver, dict):
            continue
        samples = driver.get("KnownVulnerableSamples", [])
        if not isinstance(samples, list):
            continue
        for sample in samples[:128]:
            if not isinstance(sample, dict):
                continue
            hashes = {}
            for algorithm, length in (("sha256", 64), ("sha1", 40), ("md5", 32)):
                value = sample.get(algorithm.upper(), "")
                if isinstance(value, str) and len(value) == length and all(c in "0123456789abcdefABCDEF" for c in value):
                    hashes[algorithm] = value.lower()
            if hashes:
                records.append({"id": driver.get("Id"), "tags": driver.get("Tags", [])[:20], "category": driver.get("Category"), "hashes": hashes, "filename": sample.get("Filename", ""), "description": sample.get("Description", "")})
    if not records:
        raise ValueError("La fonte LOLDrivers non contiene hash utilizzabili")
    result = {"schema": 1, "source": LOLD_URL, "retrieved_at": datetime.now(timezone.utc).isoformat(), "source_sha256": hashlib.sha256(raw).hexdigest(), "records": records, "note": "Metadati pubblici e hash, nessun download di driver."}
    save_json(tools / "loldrivers.json", result)
    return {key: value for key, value in result.items() if key != "records"} | {"record_count": len(records)}


def install_capa_rules(tools: Path) -> dict:
    commit_source = "https://api.github.com/repos/mandiant/capa-rules/commits/master"
    commit = json.loads(fetch(commit_source))["sha"]
    if not isinstance(commit, str) or len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit):
        raise ValueError("Commit capa-rules non valido")
    source = "https://codeload.github.com/mandiant/capa-rules/tar.gz/" + commit
    raw = fetch(source)
    destination = tools / "capa-rules"
    staging = Path(tempfile.mkdtemp(prefix=".capa-rules-", dir=tools))
    count, total = 0, 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            for member in archive:
                total += max(0, member.size)
                if total > 128 * 1024 * 1024 or len(archive.members) > 30000:
                    raise ValueError("Archivio capa-rules oltre i limiti, inclusi i file esclusi")
                if not member.isfile() or not member.name.endswith((".yml", ".yaml")):
                    continue
                parts = Path(member.name).parts[1:]
                if not parts or any(part in {"..", "."} for part in parts) or Path(*parts).is_absolute():
                    raise ValueError("Percorso archivio capa-rules non sicuro")
                count += 1
                if count > 20000 or total > 128 * 1024 * 1024 or member.size > 4 * 1024 * 1024:
                    raise ValueError("Archivio capa-rules oltre i limiti")
                target = staging.joinpath(*parts)
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                stream = archive.extractfile(member)
                if stream is None:
                    continue
                with stream:
                    content = stream.read(4 * 1024 * 1024 + 1)
                if len(content) > 4 * 1024 * 1024:
                    raise ValueError("Regola capa oltre il limite")
                target.write_bytes(content)
                target.chmod(0o600)
        if not count:
            raise ValueError("Archivio capa-rules privo di regole")
        if destination.exists():
            backup = tools / (".capa-rules-old-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f"))
            destination.rename(backup)
            try:
                staging.rename(destination)
            except Exception:
                backup.rename(destination)
                raise
            shutil.rmtree(backup)
        else:
            staging.rename(destination)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    result = {"source": source, "commit_source": commit_source, "commit": commit, "retrieved_at": datetime.now(timezone.utc).isoformat(), "sha256": hashlib.sha256(raw).hexdigest(), "rule_files": count, "note": "Regole dall'archivio del repository ufficiale; checksum registrato, nessuna firma verificata."}
    save_json(tools / "capa-rules-provenance.json", result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Installa strumenti affidabili in venv uv indipendenti; non esegue campioni o test.")
    parser.add_argument("--tools", type=Path, required=True)
    parser.add_argument("--component", action="append", choices=("static", "floss", "capa", "loldrivers"))
    parser.add_argument("--python", default="/usr/bin/python3")
    parser.add_argument("--allow-download", action="store_true", help="Consenso esplicito a download di strumenti e metadati pubblici, mai campioni")
    args = parser.parse_args()
    if not args.allow_download:
        parser.error("Richiesto --allow-download; nessun download o installazione effettuato")
    tools = args.tools.absolute()
    tools.mkdir(mode=0o700, parents=True, exist_ok=True)
    tools.chmod(0o700)
    results = []
    for component in dict.fromkeys(args.component or ["static", "floss", "capa", "loldrivers"]):
        if component == "loldrivers":
            results.append(install_loldrivers(tools))
        else:
            results.append(install_environment(tools, component, args.python))
            if component == "capa":
                results.append(install_capa_rules(tools))
    print(json.dumps({"installed": results}, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()

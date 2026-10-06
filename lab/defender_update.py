"""Offline Defender maintenance. Never run while the analysis service is active."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

from .bootstrap import ROOT, DEFAULT_BASE, SIDECARS, _run, _verify_network, bootstrap_lock
from .vm import AnalysisVM, MAX_ARTIFACT_BYTES, VMError, _json_write, _private_dir

SOURCE_URL = "https://go.microsoft.com/fwlink/?LinkID=121721&arch=x64"


def _require_service_stopped():
    result = subprocess.run(["systemctl", "--user", "is-active", "blacksite.service"],
                            capture_output=True, text=True, timeout=10, check=False)
    if result.stdout.strip() not in {"inactive", "failed"}:
        raise VMError("Stop blacksite.service only after every analysis has finished")


def _trusted_package(package: Path) -> tuple[Path, str]:
    package = package.absolute()
    if package.is_symlink() or package.resolve().parent != (ROOT / "data/tools/guest").resolve():
        raise VMError("Il pacchetto deve essere un file locale nella cache trusted data/tools/guest")
    if not package.is_file() or not 512 * 1024 <= package.stat().st_size <= MAX_ARTIFACT_BYTES:
        raise VMError("Pacchetto offline assente o fuori dai limiti")
    if package.stat().st_uid != os.getuid():
        raise VMError("Proprietario del pacchetto non valido")
    with package.open("rb") as stream:
        if stream.read(2) != b"MZ":
            raise VMError("Pacchetto offline non PE")
        stream.seek(0)
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    package.chmod(0o600)
    return package, digest


def refresh(base_dir: Path, package: Path) -> dict:
    _require_service_stopped()
    package, digest = _trusted_package(package)
    base_dir = base_dir.resolve()
    original = json.loads((base_dir / "metadata.json").read_text())
    if original.get("ready") is not True:
        raise VMError("Aggiornamento consentito soltanto sulla base sandbox già pronta")
    run_dir = ROOT / "data/maintenance" / ("defender-" + uuid.uuid4().hex[:12])
    vm = AnalysisVM(run_dir, base_dir, {"id": "defender-maintenance", "trace": False, "interaction": False, "_maintenance_media": True})
    pending = []
    stage = "start"
    with bootstrap_lock(base_dir):
        try:
            stage = "create_iso"
            _private_dir(run_dir)
            _run(["genisoimage", "-quiet", "-iso-level", "3", "-V", "SBDEFENDER", "-o",
                  str(run_dir / "maintenance.iso"), "-graft-points", "MPSIGN.EXE=" + str(package)], timeout=120)
            (run_dir / "maintenance.iso").chmod(0o600)
            vm.start()
            stage = "wait_agent"
            if not vm.wait_agent(240):
                raise VMError("Guest agent non disponibile")
            # Single trusted read-only CD-ROM; no shares, no guest Internet, no QGA bulk writes.
            script = r"""
$ErrorActionPreference='Stop'
$deadline=[DateTime]::UtcNow.AddSeconds(90)
do {$media=@(Get-CimInstance Win32_CDROMDrive | Where-Object {$_.Drive -and (Test-Path -LiteralPath ($_.Drive+'\MPSIGN.EXE'))});if($media.Count -eq 1){break};Start-Sleep -Seconds 2}while([DateTime]::UtcNow -lt $deadline)
if($media.Count -ne 1){throw 'CD-ROM offline di sole definizioni non disponibile'}
$file=$media[0].Drive+'\MPSIGN.EXE'
if((Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash.ToLowerInvariant() -ne 'DIGEST'){throw 'Hash pacchetto non coincidente'}
$sig=Get-AuthenticodeSignature -LiteralPath $file
if($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch '(^|,\s*)CN=Microsoft Corporation(,|$)'){throw ('Firma Microsoft non valida: '+$sig.Status)}
$before=Get-MpComputerStatus
$p=Start-Process -FilePath $file -ArgumentList '/q' -WindowStyle Hidden -PassThru
if(-not $p.WaitForExit(300000)){Stop-Process -Id $p.Id -Force;throw 'Timeout aggiornamento Defender'}
if($p.ExitCode -notin @(0,3010)){throw ('Aggiornamento Defender exit='+$p.ExitCode)}
$deadline=[DateTime]::UtcNow.AddSeconds(90)
do { $after=Get-MpComputerStatus; if($after.AMServiceEnabled -and $after.AntivirusEnabled -and $after.RealTimeProtectionEnabled -and ([DateTime]::UtcNow-$after.AntivirusSignatureLastUpdated.ToUniversalTime()).TotalDays -le 3){break};Start-Sleep -Seconds 2 } while([DateTime]::UtcNow -lt $deadline)
if(-not($after.AMServiceEnabled -and $after.AntivirusEnabled -and $after.RealTimeProtectionEnabled)){throw 'Defender deve restare attivo'}
$age=([DateTime]::UtcNow-$after.AntivirusSignatureLastUpdated.ToUniversalTime()).TotalDays
if($age -lt -1 -or $age -gt 3){throw 'Firme ancora vecchie o timestamp non valido: base non pubblicata'}
$result=@{status='updated';signature_status=[string]$sig.Status;publisher=$sig.SignerCertificate.Subject;before_version=$before.AntivirusSignatureVersion;exit_code=$p.ExitCode;snapshot=@{AMServiceEnabled=[bool]$after.AMServiceEnabled;AntivirusEnabled=[bool]$after.AntivirusEnabled;RealTimeProtectionEnabled=[bool]$after.RealTimeProtectionEnabled;AntivirusSignatureVersion=$after.AntivirusSignatureVersion;AntivirusSignatureLastUpdated=$after.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o');AMEngineVersion=$after.AMEngineVersion}}
$result | ConvertTo-Json -Depth 8 -Compress
""".replace("DIGEST", digest)
            stage = "verify_signature_and_update"
            _json_write(run_dir / "stage.json", {"stage": stage, "time": time.time()})
            rc, out, err = vm.exec(script, timeout=500)
            if rc:
                raise VMError((err or out)[-4096:])
            proof = json.loads(out.strip().lstrip("\ufeff"))
            if proof.get("status") != "updated" or proof.get("signature_status") != "Valid":
                raise VMError("Nessuna prova di aggiornamento Defender valido")
            proof.update(package_sha256=digest, package_bytes=package.stat().st_size,
                         source_url=SOURCE_URL, updated_at=time.time(), isolation=vm.isolation.copy(),
                         guest_network_proof=_verify_network(vm))
            _json_write(run_dir / "defender-update.json", proof)
            stage = "shutdown"
            if not vm.shutdown(180):
                raise VMError("Arresto non pulito: base invariata")
            # Keep the global runtime lock during flatten/publication, after shutdown releases it.
            vm._lock_runtime()
            _require_service_stopped()
            backup = ROOT / "data/base-backups" / run_dir.name
            _private_dir(backup)
            names = ("clean.qcow2", *SIDECARS, "metadata.json", "profiles.json")
            for name in names:
                _run(["cp", "--reflink=auto", "--preserve=mode", str(base_dir / name), str(backup / name)])
            stage = "flatten"
            flattened = base_dir / (".updated-" + vm.uuid + ".qcow2")
            pending.append(flattened)
            _run(["qemu-img", "convert", "-O", "qcow2", str(vm.overlay), str(flattened)])
            flattened.chmod(0o600)
            info = json.loads(_run(["qemu-img", "info", "--output=json", str(flattened)], timeout=30))
            if info.get("backing-filename"):
                raise VMError("Base aggiornata non standalone")
            replacements = {"clean.qcow2": flattened}
            for name, source in (("OVMF_VARS.fd", vm.private / "OVMF_VARS.fd"),
                                 ("tpm2-00.permall", vm.private / "tpm/tpm2-00.permall")):
                temp = base_dir / (".updated-" + name + "-" + vm.uuid)
                pending.append(temp)
                _run(["cp", "--reflink=auto", "--preserve=mode", str(source), str(temp)])
                temp.chmod(0o600)
                replacements[name] = temp
            defender = {"status": "available", "detail": "Firme aggiornate offline; firma Microsoft verificata; protezioni invariate", "snapshot": proof["snapshot"]}
            original["capabilities"]["defender"] = defender
            for profile in original.get("profiles", []):
                profile["capabilities"]["defender"] = defender
            original["defender_update"] = {"proof": str(run_dir / "defender-update.json"), "backup": str(backup), "package_sha256": digest, "updated_at": proof["updated_at"]}
            try:
                for name, source in replacements.items():
                    os.replace(source, base_dir / name)
                _json_write(base_dir / "profiles.json", original["profiles"])
                _json_write(base_dir / "metadata.json", original)
            except BaseException:
                for name in names:
                    restore = base_dir / (".restore-" + name + "-" + vm.uuid)
                    _run(["cp", "--reflink=auto", "--preserve=mode", str(backup / name), str(restore)])
                    os.replace(restore, base_dir / name)
                raise
            return {"status": "updated", "snapshot": proof["snapshot"], "proof": str(run_dir / "defender-update.json"), "backup": str(backup)}
        except Exception as exc:
            if run_dir.is_dir():
                _json_write(run_dir / "error.json", {"stage": stage, "type": type(exc).__name__, "detail": str(exc)[:4096]})
            raise
        finally:
            vm.cleanup()
            for path in pending:
                path.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description="Aggiornamento firme Defender offline in clone pulito, con rollback")
    parser.add_argument("--base-dir", type=Path, default=DEFAULT_BASE)
    parser.add_argument("--package", type=Path, default=ROOT / "data/tools/guest/mpam-fe.exe.download")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        print(json.dumps(refresh(args.base_dir, args.package), indent=2))
        return 0
    except (VMError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "error", "detail": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

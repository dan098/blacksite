"""Bounded sample parsers. This module is executed only inside the static sandbox."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import struct
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

MAX_SAMPLE = 100 * 1024 * 1024
MAX_STRINGS = 6000
MAX_STRING_LENGTH = 1024
MAX_IOCS = 500
MAX_CACHE = 64 * 1024 * 1024


def status(state: str, detail: str, result=None) -> dict:
    return {"status": state, "detail": detail, "result": result}


def identify(data: bytes, name: str) -> dict:
    extension = Path(name).suffix.lower()
    description, mime, executable = "Dati binari", "application/octet-stream", False
    signatures = (
        (b"%PDF-", "Documento PDF", "application/pdf"),
        (b"PK\x03\x04", "Archivio ZIP / documento Office Open XML", "application/zip"),
        (b"PK\x05\x06", "Archivio ZIP vuoto", "application/zip"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "Contenitore OLE / documento Office", "application/x-ole-storage"),
        (b"\x7fELF", "Eseguibile ELF (non supportato per Windows)", "application/x-elf"),
        (b"\x1f\x8b", "Archivio gzip", "application/gzip"),
        (b"7z\xbc\xaf\x27\x1c", "Archivio 7-Zip", "application/x-7z-compressed"),
        (b"Rar!\x1a\x07", "Archivio RAR", "application/vnd.rar"),
        (b"\x89PNG\r\n\x1a\n", "Immagine PNG", "image/png"),
        (b"\xff\xd8\xff", "Immagine JPEG", "image/jpeg"),
        (b"{\\rtf", "Documento RTF", "application/rtf"),
        (b"L\x00\x00\x00\x01\x14\x02\x00", "Collegamento Windows LNK", "application/x-ms-shortcut"),
        (b"MSCF", "Archivio Windows Cabinet", "application/vnd.ms-cab-compressed"),
    )
    if data.startswith(b"MZ"):
        description, mime, executable = "DOS MZ / possibile PE", "application/x-dosexec", True
        if len(data) >= 64:
            offset = struct.unpack_from("<I", data, 0x3C)[0]
            if offset <= len(data) - 4 and data[offset:offset + 4] == b"PE\x00\x00":
                description, mime = "Windows Portable Executable", "application/vnd.microsoft.portable-executable"
    else:
        for signature, label, content_type in signatures:
            if data.startswith(signature):
                description, mime = label, content_type
                break
        else:
            if not data:
                description = "File vuoto"
            elif b"\x00" not in data[:8192]:
                try:
                    text = data[:8192].decode("utf-8-sig")
                    printable = sum(c.isprintable() or c in "\r\n\t" for c in text)
                    if printable / max(len(text), 1) >= 0.95:
                        description, mime = "Testo UTF-8", "text/plain"
                        if extension in {".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".js", ".py"}:
                            description = "Script " + extension[1:].upper() + " (identificazione per estensione)"
                except UnicodeDecodeError:
                    pass
    return {"description": description, "mime": mime, "extension": extension, "executable": executable}


def extract_strings(data: bytes) -> dict:
    items = []
    total = 0
    # Bounded output even when a binary consists entirely of printable bytes.
    for encoding, pattern in (("ascii", rb"[\x20-\x7e]{4,}"), ("utf-16le", rb"(?:[\x20-\x7e]\x00){4,}"), ("utf-16be", rb"(?:\x00[\x20-\x7e]){4,}")):
        for match in re.finditer(pattern, data):
            total += 1
            if len(items) >= MAX_STRINGS:
                continue
            raw = match.group(0)
            max_bytes = MAX_STRING_LENGTH * (2 if encoding.startswith("utf-16") else 1)
            items.append({"value": raw[:max_bytes].decode(encoding), "encoding": encoding, "offset": match.start(), "truncated": len(raw) > max_bytes})
    items.sort(key=lambda item: (item["offset"], item["encoding"]))
    return {"items": items, "total": total, "truncated": total > len(items), "max_length": MAX_STRING_LENGTH}


def extract_iocs(strings: list[dict]) -> dict:
    values = {key: set() for key in ("urls", "domains", "ipv4", "emails", "paths", "registry_keys")}
    url_pattern = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'\x00]{3,512}", re.I)
    domain_pattern = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
    email_pattern = re.compile(r"\b[a-z0-9._%+-]{1,64}@[a-z0-9.-]{1,253}\.[a-z]{2,24}\b", re.I)
    path_pattern = re.compile(r"(?:[a-zA-Z]:\\|\\\\)[^\r\n\"<>|]{3,256}")
    registry_pattern = re.compile(r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\r\n\"<>]{3,256}", re.I)
    for item in strings:
        value = item["value"]
        for candidate in url_pattern.findall(value):
            candidate = candidate.rstrip(".,;)]}")
            values["urls"].add(candidate)
            try:
                host = urlsplit(candidate).hostname
                if host:
                    values["domains"].add(host.lower())
            except ValueError:
                pass
        for candidate in domain_pattern.findall(value):
            # Common file extensions must not masquerade as domains.
            if candidate.rsplit(".", 1)[-1].lower() not in {"dll", "exe", "sys", "pdb", "bat", "cmd", "ps1", "txt", "dat", "json", "xml", "log", "ini"}:
                values["domains"].add(candidate.lower())
        for candidate in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", value):
            try:
                values["ipv4"].add(str(ipaddress.IPv4Address(candidate)))
            except ipaddress.AddressValueError:
                pass
        values["emails"].update(email_pattern.findall(value))
        values["paths"].update(path_pattern.findall(value))
        values["registry_keys"].update(registry_pattern.findall(value))
        for key in values:
            if len(values[key]) > MAX_IOCS * 2:
                values[key] = set(sorted(values[key])[:MAX_IOCS])
    return {**{key: sorted(found)[:MAX_IOCS] for key, found in values.items()}, "note": "Indicatori estratti da stringhe: possibili falsi positivi, nessuna risoluzione DNS o visita degli URL.", "limit_per_category": MAX_IOCS}


def _decode(value) -> str:
    return (value or b"").decode("utf-8", errors="replace")[:512]


def signature_metadata(pe, data: bytes) -> dict:
    result = {"present": False, "verified": False, "trust": "non verificata", "certificates": [], "entries": [], "note": "Metadati della tabella certificati; nessuna verifica Authenticode, firma del contenuto, catena, revoca o fiducia."}
    directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    if len(directories) <= 4:
        return result
    security = directories[4]
    offset, size = int(security.VirtualAddress), int(security.Size)
    result.update({"offset": offset, "size": size})
    if not offset or not size:
        return result
    result["present"] = True
    if size > 8 * 1024 * 1024 or offset > len(data) or size > len(data) - offset:
        result["error"] = "Tabella certificati fuori dai limiti o eccessiva"
        return result
    end, cursor = offset + size, offset
    while cursor + 8 <= end and len(result["entries"]) < 16:
        length, revision, certificate_type = struct.unpack_from("<IHH", data, cursor)
        if length < 8 or length > end - cursor:
            result["error"] = "Record WIN_CERTIFICATE malformato"
            break
        blob = data[cursor + 8:cursor + length]
        entry = {"length": length, "revision": revision, "type": certificate_type, "sha256": hashlib.sha256(blob).hexdigest()}
        result["entries"].append(entry)
        if certificate_type == 2:
            try:
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.serialization.pkcs7 import load_der_pkcs7_certificates
                for cert in load_der_pkcs7_certificates(blob)[:16]:
                    result["certificates"].append({"subject": cert.subject.rfc4514_string()[:2048], "issuer": cert.issuer.rfc4514_string()[:2048], "serial": format(cert.serial_number, "x"), "not_before": cert.not_valid_before_utc.isoformat(), "not_after": cert.not_valid_after_utc.isoformat(), "sha256": cert.fingerprint(hashes.SHA256()).hex()})
            except ImportError:
                result["certificate_parser"] = "cryptography non installato"
            except Exception as exc:
                entry["parse_error"] = str(exc)[:256]
        cursor += (length + 7) & ~7
    return result


def parse_pe(path: Path, data: bytes) -> dict:
    if not data.startswith(b"MZ"):
        return status("unavailable", "Non è un file PE; parsing non applicabile")
    try:
        import pefile
    except ImportError:
        return status("unavailable", "pefile non installato nell'ambiente statico")
    try:
        pe = pefile.PE(str(path), fast_load=True)
        try:
            if int(pe.FILE_HEADER.NumberOfSections) > 96:
                return status("error", "Numero di sezioni PE oltre il limite (96)")
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"], pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
            imports, exports, sections = [], [], []
            imported_count = 0
            truncated_imports = False
            for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])[:128]:
                functions = []
                for function in descriptor.imports:
                    if imported_count >= 4096:
                        truncated_imports = True
                        break
                    functions.append({"name": _decode(function.name) or None, "ordinal": function.ordinal, "address": int(function.address)})
                    imported_count += 1
                imports.append({"dll": _decode(descriptor.dll), "functions": functions})
                if truncated_imports:
                    break
            for function in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", [])[:2048]:
                exports.append({"name": _decode(function.name) or None, "ordinal": int(function.ordinal), "address": int(function.address), "forwarder": _decode(function.forwarder) or None})
            for section in pe.sections[:96]:
                flags = int(section.Characteristics)
                sections.append({"name": _decode(section.Name).rstrip("\x00"), "virtual_address": int(section.VirtualAddress), "virtual_size": int(section.Misc_VirtualSize), "raw_size": int(section.SizeOfRawData), "raw_offset": int(section.PointerToRawData), "entropy": round(section.get_entropy(), 4), "characteristics": flags, "readable": bool(flags & 0x40000000), "writable": bool(flags & 0x80000000), "executable": bool(flags & 0x20000000)})
            timestamp = int(pe.FILE_HEADER.TimeDateStamp)
            overlay = pe.get_overlay_data_start_offset()
            warnings = [str(item)[:512] for item in pe.get_warnings()[:32]]
            if any(section["writable"] and section["executable"] for section in sections):
                warnings.append("Sezione scrivibile ed eseguibile: indicatore euristico, non prova di malware")
            if any(section["entropy"] >= 7.2 and section["raw_size"] >= 1024 for section in sections):
                warnings.append("Sezione ad alta entropia: possibile compressione o cifratura, non prova di malware")
            return status("completed", "PE analizzato senza esecuzione; firma non verificata", {"machine": pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine)), "machine_id": int(pe.FILE_HEADER.Machine), "timestamp": timestamp, "timestamp_utc": datetime.fromtimestamp(timestamp, timezone.utc).isoformat(), "entrypoint": int(pe.OPTIONAL_HEADER.AddressOfEntryPoint), "imagebase": int(pe.OPTIONAL_HEADER.ImageBase), "subsystem": int(pe.OPTIONAL_HEADER.Subsystem), "is_dll": bool(pe.FILE_HEADER.Characteristics & 0x2000), "imphash": pe.get_imphash(), "sections": sections, "imports": imports, "imports_truncated": truncated_imports, "exports": exports, "overlay_size": len(data) - overlay if overlay is not None else 0, "signature": signature_metadata(pe, data), "warnings": warnings})
        finally:
            pe.close()
    except Exception as exc:
        return status("error", "PE malformato o parsing fallito: " + str(exc)[:512])


def yara_scan(path: Path, rules_dir: Path) -> dict:
    try:
        import yara
    except ImportError:
        return status("unavailable", "yara-python non installato nell'ambiente statico")
    files = sorted(rules_dir.glob("*.yar"))[:32]
    if not files:
        return status("unavailable", "Nessuna regola YARA locale disponibile")
    try:
        rules = yara.compile(filepaths={file.stem: str(file) for file in files})
        matches = []
        for match in rules.match(str(path), timeout=15)[:100]:
            evidence = []
            for item in match.strings:
                # yara-python >=4.3 exposes StringMatchInstance rather than tuples.
                if isinstance(item, tuple):
                    offset, identifier, value = item
                    evidence.append({"identifier": identifier, "offset": offset, "value": value[:128].decode("utf-8", errors="replace")})
                else:
                    for instance in item.instances[:8]:
                        evidence.append({"identifier": item.identifier, "offset": instance.offset, "value": instance.matched_data[:128].decode("utf-8", errors="replace")})
                if len(evidence) >= 32:
                    break
            matches.append({"rule": match.rule, "namespace": match.namespace, "tags": match.tags, "meta": match.meta, "strings": evidence[:32]})
        return status("completed", "Regole euristiche locali: corrispondenze non equivalgono a un verdetto", {"matches": matches, "rulesets": [file.name for file in files], "heuristic": True})
    except yara.TimeoutError:
        return status("timeout", "Timeout della scansione YARA")
    except Exception as exc:
        return status("error", "YARA: " + str(exc)[:512])


def driver_assessment(pe_result: dict, strings: list[dict], hashes: dict, cache: Path | None, name: str) -> dict:
    indicators = []
    pe = pe_result.get("result") or {}
    libraries = {entry["dll"].lower() for entry in pe.get("imports", [])}
    functions = {function["name"] for entry in pe.get("imports", []) for function in entry["functions"] if function["name"]}
    kernel_import = bool(libraries.intersection({"ntoskrnl.exe", "hal.dll", "wdfldr.sys", "fltmgr.sys"}))
    if kernel_import:
        indicators.append({"kind": "kernel_imports", "evidence": sorted(libraries.intersection({"ntoskrnl.exe", "hal.dll", "wdfldr.sys", "fltmgr.sys"})), "label": "Importazioni compatibili con un driver kernel"})
    if Path(name).suffix.lower() == ".sys":
        indicators.append({"kind": "extension", "evidence": ".sys", "label": "Estensione driver: non dimostra formato né vulnerabilità"})
    risky = sorted(functions.intersection({"MmMapIoSpace", "MmMapIoSpaceEx", "MmCopyMemory", "ZwTerminateProcess", "ZwOpenProcess", "ObOpenObjectByPointer", "ZwLoadDriver", "PsLookupProcessByProcessId", "MmMapLockedPagesSpecifyCache"}))
    if risky:
        indicators.append({"kind": "sensitive_driver_apis", "evidence": risky, "label": "API sensibili presenti anche in driver legittimi"})
    device_strings = [item["value"] for item in strings if "\\Device\\" in item["value"] or "\\DosDevices\\" in item["value"]][:20]
    if device_strings:
        indicators.append({"kind": "device_names", "evidence": device_strings, "label": "Possibile interfaccia dispositivo; nessuna analisi di vulnerabilità IOCTL"})
    result = {"known_vulnerable_hash_matches": [], "indicators": indicators, "candidate": kernel_import or (bool(pe) and Path(name).suffix.lower() == ".sys"), "proof": False, "cache": None, "note": "Indicatori statici BYOVD, non prova di exploit o caricamento. Non viene installato alcun driver."}
    if cache is None or not cache.is_file():
        return status("unavailable", "Cache LOLDrivers assente; solo indicatori euristici disponibili", result)
    try:
        if cache.stat().st_size > MAX_CACHE:
            raise ValueError("Cache LOLDrivers oltre 64 MiB")
        payload = json.loads(cache.read_bytes())
        if isinstance(payload, list):
            records = payload
            result["cache"] = {"source": "Cache locale formato LOLDrivers; provenienza non verificata", "records": len(records)}
        elif isinstance(payload, dict) and isinstance(payload.get("records"), list):
            records = payload["records"]
            result["cache"] = {key: payload.get(key) for key in ("source", "retrieved_at", "source_sha256")}
            result["cache"]["records"] = len(records)
        else:
            raise ValueError("Formato cache LOLDrivers non riconosciuto")
        if len(records) > 40000:
            raise ValueError("Troppi record LOLDrivers")
        for record in records:
            if not isinstance(record, dict):
                continue
            samples = record.get("KnownVulnerableSamples", [record])
            if not isinstance(samples, list):
                continue
            for sample in samples[:128]:
                if not isinstance(sample, dict):
                    continue
                sample_hashes = sample.get("hashes", sample)
                if not isinstance(sample_hashes, dict):
                    continue
                for algorithm in ("sha256", "sha1", "md5"):
                    expected = sample_hashes.get(algorithm, sample_hashes.get(algorithm.upper(), ""))
                    if isinstance(expected, str) and expected.lower() == hashes.get(algorithm):
                        result["known_vulnerable_hash_matches"].append({"id": record.get("Id", record.get("id")), "tags": record.get("Tags", record.get("tags", [])), "category": record.get("Category", record.get("category")), "filename": sample.get("Filename", sample.get("filename")), "algorithm": algorithm, "hash": expected.lower(), "description": sample.get("Description", sample.get("description")), "source": "LOLDrivers (cache locale)", "byovd_observed": False})
                        break
                if len(result["known_vulnerable_hash_matches"]) >= 100:
                    break
            if len(result["known_vulnerable_hash_matches"]) >= 100:
                break
        return status("completed", "Confronto hash con cache LOLDrivers; assenza di corrispondenze non prova sicurezza", result)
    except Exception as exc:
        return status("error", "Cache LOLDrivers non utilizzabile: " + str(exc)[:256], result)


def parse_sample(sample: Path, name: str, rules: Path, cache: Path | None) -> dict:
    if sample.stat().st_size > MAX_SAMPLE:
        raise ValueError("Campione oltre il limite di 100 MiB")
    data = sample.read_bytes()
    if len(data) > MAX_SAMPLE:
        raise ValueError("Campione cresciuto oltre il limite")
    hashes = {algorithm: hashlib.new(algorithm, data, usedforsecurity=False).hexdigest() for algorithm in ("md5", "sha1", "sha256")}
    strings = extract_strings(data)
    pe = parse_pe(sample, data)
    return {"type": identify(data, name), "pe": pe, "strings": status("completed", "Stringhe ASCII / UTF-16 LE e BE; numero e lunghezza limitati", strings), "iocs": status("completed", "Indicatori testuali, nessun accesso alla rete", extract_iocs(strings["items"])), "yara": yara_scan(sample, rules), "byovd": driver_assessment(pe, strings["items"], hashes, cache, name)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample", type=Path, required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--loldrivers", type=Path)
    args = parser.parse_args()
    try:
        payload = parse_sample(args.sample, args.name, args.rules, args.loldrivers)
    except Exception as exc:
        payload = {"fatal": "Analisi statica fallita: " + str(exc)[:512]}
    print(json.dumps(payload, ensure_ascii=True, separators=(",", ":")))


if __name__ == "__main__":
    main()

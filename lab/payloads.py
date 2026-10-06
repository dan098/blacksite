"""Bounded, private secondary-payload evidence. Never execute or extract content.

Guest manifests are attacker-controlled even when their directory was allocated
by the worker. Candidate names are not verified artifacts: only read_payloads()
adds a name to artifact_names after independently reading and hashing its bytes.
"""
from __future__ import annotations

import hashlib
import json
import ntpath
import os
import re
import stat
from datetime import datetime
from pathlib import Path
from typing import Any

MANIFEST_NAME = "payloads.json"
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_FILES = 16
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_RECORDS = 256
_ARTIFACT = re.compile(r"payload-(00[0-9]|01[0-5])-([0-9a-f]{64})\.bin\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_EXTENSIONS = {".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".msi", ".scr", ".jar", ".zip"}
_STATUSES = {"collected", "missing", "deleted", "unavailable", "over_limit", "rejected", "error"}


def _integer(value: Any, maximum: int) -> bool:
    return type(value) is int and 0 <= value <= maximum


def _text(value: Any, maximum: int = 2048) -> str:
    return value if isinstance(value, str) and len(value) <= maximum else ""


def _source_error(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 2048:
        return "invalid_source_path"
    if not value.startswith(("C:\\", "c:\\")) or "/" in value or any(ord(c) < 32 for c in value):
        return "unsafe_source_path"
    parts = value[3:].split("\\")
    if not parts or any(not p or p in {".", ".."} or p.endswith((".", " ")) or
                        any(c in p for c in ':*?"<>|') for p in parts):
        return "unsafe_source_path"
    # Windows device aliases are not ordinary files, even with an extension.
    if any(re.fullmatch(r"(?:con|conin\$|conout\$|prn|aux|nul|com[0-9\u00b9\u00b2\u00b3]|lpt[0-9\u00b9\u00b2\u00b3])", p.split(".", 1)[0].rstrip(" "), re.I)
           for p in parts):
        return "unsafe_source_path"
    if ntpath.splitext(value)[1].lower() not in _EXTENSIONS:
        return "unsupported_extension"
    return ""


def _open_regular(directory_fd: int, name: str, maximum: int):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    fd = os.open(name, flags, dir_fd=directory_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("not_regular_file")
        if info.st_nlink != 1:
            raise ValueError("hardlinked_file")
        if info.st_size > maximum:
            raise ValueError("size_limit")
        return fd, info
    except BaseException:
        os.close(fd)
        raise


def _no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_manifest_key")
        result[key] = value
    return result


def _directory(run_dir: Path | str) -> int:
    # Pin every component without following symlinks; a check-then-open race is
    # not sufficient on a writable evidence directory.
    absolute = Path(os.path.abspath(os.fspath(run_dir)))
    fd = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in absolute.parts[1:]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _manifest(directory_fd: int) -> dict:
    fd, before = _open_regular(directory_fd, MANIFEST_NAME, MAX_MANIFEST_BYTES)
    with os.fdopen(fd, "rb") as stream:
        raw = stream.read(MAX_MANIFEST_BYTES + 1)
        after = os.fstat(stream.fileno())
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("manifest_size_limit")
    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError("manifest_changed_while_reading")
    result = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_no_duplicate_keys,
                        parse_constant=lambda value: (_ for _ in ()).throw(ValueError("invalid_json_constant")))
    if not isinstance(result, dict) or type(result.get("schema_version")) is not int or result["schema_version"] != 1:
        raise ValueError("unsupported_manifest_schema")
    if not isinstance(result.get("payloads"), list) or len(result["payloads"]) > MAX_RECORDS:
        raise ValueError("manifest_record_limit")
    if result.get("status") not in {"completed", "partial", "unavailable", "error"}:
        raise ValueError("invalid_manifest_status")
    if type(result.get("truncated")) is not bool:
        raise ValueError("invalid_manifest_truncated_flag")
    return result


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or len(value) > 128:
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result if result.tzinfo is not None else None
    except ValueError:
        return None


def _event_reference(value: Any) -> dict:
    value = value if isinstance(value, dict) else {}
    return {"source": _text(value.get("source"), 32),
            "event_id": value.get("event_id") if _integer(value.get("event_id"), 65535) else None,
            "record_id": value.get("record_id") if _integer(value.get("record_id"), (1 << 63) - 1) else None,
            "index": value.get("index") if _integer(value.get("index"), 49999) else None,
            "time": _text(value.get("time"), 128)}


def _identity(value: Any) -> tuple[dict, bool]:
    if not isinstance(value, dict):
        return {}, False
    result = {key: _text(value.get(key), 1024) for key in
              ("identity", "guid", "start_time", "image", "identity_source", "parent_identity")}
    result["pid"] = value.get("pid") if _integer(value.get("pid"), 0xFFFFFFFF) else None
    basis_valid = (result["identity_source"] == "sysmon_guid" and bool(result["guid"]) and
                   result["identity"].casefold() == result["guid"].casefold()) or (
                   result["identity_source"] == "pid_time" and not result["guid"] and
                   result["identity"].startswith(f"pid:{result['pid']}:{result['start_time']}:"))
    valid = bool(result["identity"] and _timestamp(result["start_time"]) and result["pid"] and basis_valid)
    return result, valid


def _record(raw: Any) -> tuple[dict, list[str]]:
    invalid_record = not isinstance(raw, dict)
    if invalid_record:
        raw = {}
    process, identity_valid = _identity(raw.get("source_process"))
    event_ref = _event_reference(raw.get("event_ref"))
    result = {
        "index": raw.get("index"), "artifact_index": raw.get("artifact_index"),
        "source_path": _text(raw.get("source_path")),
        "source_process": process, "event_ref": event_ref,
        "guest_status": _text(raw.get("status"), 32), "status": _text(raw.get("status"), 32),
        "size": raw.get("size"), "sha256": _text(raw.get("sha256"), 64),
        "artifact_name": "", "flags": [], "detail": _text(raw.get("detail"), 512),
        "verification": "metadata_only", "trust": "untrusted_guest_metadata", "observed_uses": [],
    }
    flags = raw.get("flags")
    if isinstance(flags, list):
        result["flags"] = [_text(flag, 128) for flag in flags[:32] if _text(flag, 128)]
    uses = raw.get("observed_uses")
    if isinstance(uses, list):
        for use in uses[:16]:
            if not isinstance(use, dict):
                continue
            process_use, _ = _identity(use.get("process"))
            result["observed_uses"].append({"process": process_use, "association": _text(use.get("association"), 64),
                                           "event_ref": _event_reference(use.get("event_ref"))})
    issues = ["invalid_record"] if invalid_record else []
    if not _integer(raw.get("index"), MAX_RECORDS - 1):
        issues.append("invalid_index")
    if result["guest_status"] not in _STATUSES:
        issues.append("invalid_status")
    if not identity_valid:
        issues.append("missing_source_identity")
    if event_ref["source"] != "sysmon" or event_ref["event_id"] != 11 or not _timestamp(event_ref["time"]):
        issues.append("invalid_event_reference")
    elif identity_valid and _timestamp(event_ref["time"]) < _timestamp(process["start_time"]):
        issues.append("event_before_source_process")
    if event_ref["record_id"] is None and event_ref["index"] is None:
        issues.append("missing_event_reference")
    if raw.get("size") is not None and not _integer(raw["size"], (1 << 63) - 1):
        issues.append("invalid_size")
    if result["guest_status"] == "collected":
        source_issue = _source_error(raw.get("source_path"))
        if source_issue:
            issues.append(source_issue)
        if not _integer(raw.get("artifact_index"), MAX_FILES - 1):
            issues.append("artifact_index_limit")
        if not _integer(raw.get("size"), MAX_FILE_BYTES):
            issues.append("file_size_limit")
        digest = result["sha256"]
        if not _SHA256.fullmatch(digest):
            issues.append("invalid_sha256")
        expected = f"payload-{raw['artifact_index']:03d}-{digest}.bin" if _integer(raw.get("artifact_index"), MAX_FILES - 1) and _SHA256.fullmatch(digest) else ""
        supplied = raw.get("artifact_name")
        if not expected or supplied != expected or not _ARTIFACT.fullmatch(supplied):
            issues.append("unsafe_artifact_name")
        else:
            result["artifact_name"] = expected
    elif raw.get("artifact_name") not in (None, "") or raw.get("sha256") not in (None, ""):
        issues.append("unexpected_artifact_for_metadata")
    if issues:
        result["verification"] = "untrusted"
        result["status"] = "untrusted"
    result["validation_errors"] = issues
    return result, issues


def _validated_records(manifest: dict) -> list[dict]:
    records = [_record(raw)[0] for raw in manifest["payloads"]]
    names: set[str] = set()
    indices: set[int] = set()
    artifact_indices: set[int] = set()
    total = count = 0
    for record in records:
        index = record["index"]
        if type(index) is int and index in indices:
            record["validation_errors"].append("duplicate_index")
        elif type(index) is int:
            indices.add(index)
        if record["guest_status"] == "collected":
            slot = record["artifact_index"]
            if type(slot) is int and slot in artifact_indices:
                record["validation_errors"].append("duplicate_artifact_index")
            elif type(slot) is int:
                artifact_indices.add(slot)
            name = record["artifact_name"]
            if name and name in names:
                record["validation_errors"].append("duplicate_artifact")
            elif name:
                names.add(name)
            if not record["validation_errors"]:
                count += 1
                total += record["size"]
                if count > MAX_FILES or total > MAX_TOTAL_BYTES:
                    record["validation_errors"].append("total_budget_limit")
        if record["validation_errors"]:
            record["verification"] = "untrusted"
            record["status"] = "untrusted"
    return records


def payload_artifact_candidates(run_dir: Path | str) -> list[str]:
    """Names safe to request from the guest, NOT content-verified/registrable.

    Pull payloads.json first (<=1 MiB), then each candidate with a 16 MiB cap
    and a 64 MiB aggregate cap. Call read_payloads() after pulling bytes.
    """
    try:
        fd = _directory(run_dir)
        try:
            return [r["artifact_name"] for r in _validated_records(_manifest(fd))
                    if r["guest_status"] == "collected" and not r["validation_errors"]]
        finally:
            os.close(fd)
    except (OSError, ValueError, TypeError, RecursionError, UnicodeError):
        return []


def read_payloads(run_dir: Path | str) -> dict:
    """Load private manifest metadata; recompute every successful SHA256.

    SHA256 verification proves agreement with bytes, NOT guest attribution,
    authenticity, safety, or that a command-line reference was executed.
    All paths and artifact names in this return value belong in private reports.
    """
    result = {"schema_version": 1, "status": "unavailable", "payloads": [], "artifact_names": [],
              "manifest_name": MANIFEST_NAME, "trust": "untrusted_guest_metadata",
              "budgets": {"max_files": MAX_FILES, "max_file_bytes": MAX_FILE_BYTES,
                          "max_total_bytes": MAX_TOTAL_BYTES, "max_manifest_bytes": MAX_MANIFEST_BYTES,
                          "max_metadata_records": MAX_RECORDS, "verified_files": 0, "verified_bytes": 0,
                          "bytes_read": 0}, "warnings": [], "errors": []}
    try:
        fd = _directory(run_dir)
    except (OSError, ValueError, TypeError) as exc:
        result["status"] = "error"
        result["errors"].append(f"run_directory_rejected:{type(exc).__name__}")
        return result
    try:
        try:
            manifest = _manifest(fd)
        except FileNotFoundError:
            result["warnings"].append("payload_manifest_unavailable")
            return result
        except (OSError, ValueError, TypeError, RecursionError, UnicodeError) as exc:
            result["status"] = "untrusted"
            result["errors"].append(f"manifest_rejected:{type(exc).__name__}:{str(exc)[:128]}")
            return result
        result["guest_status"] = _text(manifest.get("status"), 32)
        result["guest_budgets"] = manifest.get("budgets") if isinstance(manifest.get("budgets"), dict) else {}
        result["root_process"], _ = _identity(manifest.get("root_process"))
        result["truncated"] = manifest.get("truncated") is True
        result["payloads"] = _validated_records(manifest)
        result["warnings"].append("Guest metadata/attribution untrusted; verified hashes do not establish safety.")
        if result["truncated"]:
            result["warnings"].append("payload_metadata_truncated")
        for record in result["payloads"]:
            if record["validation_errors"]:
                continue
            if record["guest_status"] != "collected":
                continue
            if result["budgets"]["bytes_read"] + record["size"] > MAX_TOTAL_BYTES:
                record["status"] = record["verification"] = "untrusted"
                record["validation_errors"].append("read_budget_limit")
                continue
            try:
                artifact_fd, before = _open_regular(fd, record["artifact_name"], MAX_FILE_BYTES)
                digest = hashlib.sha256()
                size = 0
                with os.fdopen(artifact_fd, "rb") as stream:
                    if before.st_size != record["size"]:
                        raise ValueError("size_mismatch")
                    while True:
                        remaining = min(MAX_FILE_BYTES - size, MAX_TOTAL_BYTES - result["budgets"]["bytes_read"])
                        if remaining <= 0:
                            break
                        block = stream.read(min(65536, remaining))
                        if not block:
                            break
                        size += len(block)
                        result["budgets"]["bytes_read"] += len(block)
                        if size > MAX_FILE_BYTES or result["budgets"]["bytes_read"] > MAX_TOTAL_BYTES:
                            raise ValueError("read_budget_limit")
                        digest.update(block)
                    after = os.fstat(stream.fileno())
                record["actual_size"] = size
                record["actual_sha256"] = digest.hexdigest()
                if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    raise ValueError("artifact_changed_while_reading")
                if size != record["size"]:
                    raise ValueError("size_mismatch")
                if digest.hexdigest() != record["sha256"]:
                    raise ValueError("sha256_mismatch")
                record["verification"] = "verified"
                record["status"] = "verified"
                result["artifact_names"].append(record["artifact_name"])
                result["budgets"]["verified_files"] += 1
                result["budgets"]["verified_bytes"] += size
            except FileNotFoundError:
                record["verification"] = record["status"] = "error"
                record["validation_errors"].append("artifact_missing")
            except (OSError, ValueError) as exc:
                record["verification"] = record["status"] = "untrusted"
                record["validation_errors"].append(f"artifact_rejected:{str(exc)[:128]}")
        states = {record["verification"] for record in result["payloads"]}
        if "untrusted" in states:
            result["status"] = "untrusted"
        elif "error" in states:
            result["status"] = "partial"
        elif result["truncated"] or result["guest_status"] in {"partial", "error", "unavailable"} or any(
                r["guest_status"] != "collected" for r in result["payloads"]):
            result["status"] = "partial" if result["payloads"] else result["guest_status"] or "partial"
        else:
            result["status"] = "completed"
        return result
    finally:
        os.close(fd)

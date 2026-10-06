from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
from pathlib import Path

import pytest

from lab import static_analysis as engine
from lab import static_worker as parser


EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def _pe_fixture(signature=False) -> bytes:
    """Inert, authored PE headers for parsing; never execute this fixture."""
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 4, 512)
    struct.pack_into("<IIQ", data, optional + 16, 0x1000, 0x1000, 0x140000000)
    struct.pack_into("<II", data, optional + 32, 4096, 512)
    struct.pack_into("<HH", data, optional + 40, 6, 0)
    struct.pack_into("<II", data, optional + 56, 8192, 512)
    struct.pack_into("<HH", data, optional + 68, 3, 0x8160)
    struct.pack_into("<QQQQ", data, optional + 72, 0x100000, 0x1000, 0x100000, 0x1000)
    struct.pack_into("<I", data, optional + 108, 16)
    struct.pack_into("<8sIIIIIIHHI", data, 0x188, b".text\x00\x00\x00", 1, 4096, 512, 512, 0, 0, 0, 0, 0x60000020)
    data[512] = 0xC3
    if signature:
        struct.pack_into("<II", data, optional + 112 + 4 * 8, 1024, 16)
        data.extend(struct.pack("<IHH8s", 16, 0x200, 1, b"metadata"))
    return bytes(data)


def _no_av(monkeypatch):
    monkeypatch.setattr(engine, "_clamav", lambda *args: engine._status("unavailable", "Motore disabilitato dal test"))
    monkeypatch.setattr(engine, "_hash_reputation", lambda *args: engine._status("unavailable", "Rete disabilitata dal test"))


def test_hashes_are_real_and_regular_files_only(tmp_path):
    sample = tmp_path / "sample.txt"
    sample.write_bytes(b"authored test bytes")
    size, hashes = engine._hash_sample(sample)
    assert size == sample.stat().st_size
    assert hashes["sha256"] == hashlib.sha256(sample.read_bytes()).hexdigest()
    linked = tmp_path / "linked"
    linked.symlink_to(sample)
    with pytest.raises(OSError):
        engine._hash_sample(linked)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match="regolare"):
        engine._hash_sample(fifo)


def test_oversized_samples_rejected_before_reading(tmp_path, monkeypatch):
    sample = tmp_path / "too-big"
    sample.write_bytes(b"12345")
    monkeypatch.setattr(engine, "MAX_SAMPLE", 4)
    with pytest.raises(ValueError, match="limite"):
        engine._hash_sample(sample)


def test_strings_encodings_and_iocs_are_inert():
    data = b"https://sample.example/path\x00" + "HKCU\\Software\\Demo".encode("utf-16le") + b"\x00\x00" + "test@sample.example".encode("utf-16be") + b"\x00" + b"192.0.2.12 999.999.999.999 kernel32.dll C:\\Temp\\demo.exe"
    strings = parser.extract_strings(data)
    assert {item["encoding"] for item in strings["items"]} == {"ascii", "utf-16le", "utf-16be"}
    iocs = parser.extract_iocs(strings["items"])
    assert "https://sample.example/path" in iocs["urls"]
    assert "sample.example" in iocs["domains"]
    assert "kernel32.dll" not in iocs["domains"]
    assert "192.0.2.12" in iocs["ipv4"]
    assert "999.999.999.999" not in iocs["ipv4"]
    assert "test@sample.example" in iocs["emails"]
    assert "HKCU\\Software\\Demo" in iocs["registry_keys"]


def test_strings_have_count_and_length_bounds(monkeypatch):
    monkeypatch.setattr(parser, "MAX_STRINGS", 3)
    monkeypatch.setattr(parser, "MAX_STRING_LENGTH", 8)
    found = parser.extract_strings(b"A" * 1024 + b"\x00BBBB\x00CCCC\x00DDDD\x00EEEE")
    assert found["total"] == 5
    assert len(found["items"]) == 3
    assert found["truncated"]
    assert found["items"][0]["truncated"]
    assert len(found["items"][0]["value"]) == 8


def test_identification_does_not_trust_extension():
    identified = parser.identify(b"plain authored text", "fake.exe")
    assert not identified["executable"]
    assert identified["mime"] == "text/plain"
    assert parser.identify(_pe_fixture(), "headers.bin")["mime"] == "application/vnd.microsoft.portable-executable"
    assert parser.identify(b"PK\x03\x04", "archive.exe")["mime"] == "application/zip"


def test_loldrivers_matches_both_official_and_normalized_cache(tmp_path):
    hashes = {"sha256": "a" * 64, "md5": "b" * 32, "sha1": "c" * 40}
    cache = tmp_path / "drivers.json"
    pe = parser.status("completed", "test", {"imports": [{"dll": "ntoskrnl.exe", "functions": [{"name": "MmMapIoSpace"}]}]})
    for payload in ([{"Id": "known-driver", "Category": "vulnerable", "Tags": ["demo.sys"], "KnownVulnerableSamples": [{"SHA256": hashes["sha256"], "Filename": "demo.sys"}]}], {"source": "official test", "retrieved_at": "2026-01-01", "records": [{"id": "known-driver", "hashes": hashes, "filename": "demo.sys"}]}):
        cache.write_text(json.dumps(payload))
        assessment = parser.driver_assessment(pe, [], hashes, cache, "demo.sys")
        assert assessment["status"] == "completed"
        assert assessment["result"]["candidate"]
        assert assessment["result"]["known_vulnerable_hash_matches"][0]["algorithm"] == "sha256"
        assert not assessment["result"]["proof"]
        assert not assessment["result"]["known_vulnerable_hash_matches"][0]["byovd_observed"]


def test_missing_loldrivers_preserves_indicators_without_fake_clean():
    assessment = parser.driver_assessment(parser.status("unavailable", "not PE"), [], {}, None, "not-really.sys")
    assert assessment["status"] == "unavailable"
    assert not assessment["result"]["candidate"]
    assert assessment["result"]["indicators"]
    assert not assessment["result"]["proof"]


def test_malformed_loldrivers_is_error_not_no_matches(tmp_path):
    cache = tmp_path / "broken.json"
    cache.write_text("{bad")
    assessment = parser.driver_assessment({}, [], {}, cache, "sample.bin")
    assert assessment["status"] == "error"


def test_missing_isolation_never_falls_back_to_host(tmp_path, monkeypatch):
    sample = tmp_path / "sample.txt"
    sample.write_bytes(b"test authored input")
    monkeypatch.setattr(engine, "_hash_reputation", lambda *a: engine._status("unavailable", "Disabled for test"))
    monkeypatch.setattr(engine.shutil, "which", lambda name: None)
    monkeypatch.setattr(engine.subprocess, "Popen", lambda *a, **kw: pytest.fail("No host subprocess allowed without isolation"))
    result = engine.analyze(sample, tmp_path / "artifacts", tmp_path / "tools")
    assert result["hashes"]["sha256"]
    assert result["strings"]["status"] == "unavailable"
    assert result["yara"]["status"] == "unavailable"
    assert result["av"]["status"] == "unavailable"
    assert not result["capabilities"]["sandbox"]["result"]["verified"]
    assert "safe" not in result
    assert (tmp_path / "artifacts" / "static.json").is_file()


def test_sandbox_command_has_no_root_or_home_bind(tmp_path, monkeypatch):
    sample = tmp_path / "sample"
    sample.write_bytes(b"authored")
    monkeypatch.setattr(engine.shutil, "which", lambda name: "/usr/bin/" + name)
    command = engine._sandbox_command(sample, tmp_path / "tools", Path(sys.executable), ["/app/static_worker.py"], 5, [(engine.WORKER, "/app/static_worker.py")])
    assert "--unshare-all" in command and "--unshare-net" in command
    assert "--clearenv" in command and "--die-with-parent" in command
    assert "--as=" + str(engine.MEMORY_LIMIT) in command
    assert "--remount-ro" in command
    for index, argument in enumerate(command):
        if argument == "--ro-bind":
            assert command[index + 1] not in {"/", str(Path.home())}
    assert str(sample) in command and "/sample/input" in command
    assert "VT_API_KEY" not in command


def test_tool_output_and_time_are_bounded(monkeypatch):
    monkeypatch.setattr(engine, "MAX_STDOUT", 1024)
    result = engine._run([sys.executable, "-c", "import sys; sys.stdout.write('x'*10000)"], 5)
    assert result["status"] == "error"
    assert len(result["result"]["stdout"]) <= 1024
    assert result["result"]["output_truncated"]
    result = engine._run([sys.executable, "-c", "import time; time.sleep(5)"], 1)
    assert result["status"] == "timeout"


def test_reputation_default_has_no_network(monkeypatch):
    monkeypatch.delenv("SANDBOX_VT_HASH_LOOKUP", raising=False)
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.setattr(engine, "build_opener", lambda *a: pytest.fail("Network lookup disabled"))
    result = engine._hash_reputation("a" * 64)
    assert result["status"] == "unavailable"
    assert not result["result"]["enabled"]
    assert not result["result"]["uploads"]


def test_no_clamav_database_is_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "_clam_database", lambda tools: None)
    monkeypatch.setattr(engine.shutil, "which", lambda name: "/usr/bin/" + name)
    assert engine.capabilities(tmp_path)["clamav"]["status"] == "unavailable"


def test_clamav_real_returncode_not_synthetic_detection(tmp_path, monkeypatch):
    cap = engine._status("available", "test", {"path": "/usr/bin/clamscan", "database": str(tmp_path)})
    output = "/sample/input: Eicar-Signature FOUND\nEngine version: 1.4.3\n"
    monkeypatch.setattr(engine, "_isolated", lambda *a, **kw: engine._status("completed", "test", {"returncode": 1, "stdout": output, "stderr": ""}))
    result = engine._clamav(tmp_path / "sample", tmp_path, cap)
    assert result["result"]["infected"]
    assert result["result"]["detections"] == ["Eicar-Signature"]
    assert result["result"]["engine_version"] == "1.4.3"


def test_clamav_limit_indicator_is_incomplete_not_infection(tmp_path, monkeypatch):
    cap = engine._status("available", "test", {"path": "/usr/bin/clamscan", "database": str(tmp_path)})
    output = "/sample/input: Heuristics.Limits.Exceeded.MaxScanSize FOUND\n"
    monkeypatch.setattr(engine, "_isolated", lambda *a, **kw: engine._status("completed", "test", {"returncode": 1, "stdout": output, "stderr": ""}))
    result = engine._clamav(tmp_path / "sample", tmp_path, cap)
    assert result["status"] == "error"
    assert result["result"]["infected"] is None
    assert not result["result"]["scan_complete"]
    assert result["result"]["limits_exceeded"]


@pytest.mark.parametrize("content,name", [(EICAR, "eicar.txt"), (_pe_fixture(signature=True), "headers.exe"), (b"MZ" + b"\x00" * 64, "broken.exe")])
def test_networkless_static_end_to_end(tmp_path, monkeypatch, content, name):
    if not engine.shutil.which("bwrap") or not engine.shutil.which("prlimit"):
        pytest.skip("Bubblewrap/prlimit are not installed")
    _no_av(monkeypatch)
    sample = tmp_path / name
    sample.write_bytes(content)
    result = engine.analyze(sample, tmp_path / "artifacts", tmp_path / "tools")
    if result["strings"]["status"] != "completed":
        # Hosts disabling unprivileged user namespaces must fail closed.
        assert result["pe"]["status"] in {"unavailable", "error", "timeout"}
        assert not result["capabilities"]["sandbox"]["result"]["verified"]
        pytest.skip("Required isolation blocked on this host: " + result["strings"]["detail"])
    assert result["capabilities"]["sandbox"]["result"]["verified"]
    assert not result["capabilities"]["sandbox"]["result"]["network"]
    assert result["hashes"]["sha256"] == hashlib.sha256(content).hexdigest()
    if name == "eicar.txt" and result["yara"]["status"] != "unavailable":
        assert result["yara"]["status"] == "completed", result["yara"]
        rules = {match["rule"] for match in result["yara"]["result"]["matches"]}
        assert "Lab_EICAR_TestMarker" in rules
        assert result["pe"]["status"] == "unavailable"
        assert result["floss"]["status"] == "unavailable"
    elif name == "headers.exe" and result["pe"]["status"] != "unavailable":
        assert result["pe"]["status"] == "completed", result["pe"]
        pe = result["pe"]["result"]
        assert pe["machine"] == "IMAGE_FILE_MACHINE_AMD64"
        assert pe["sections"][0]["name"] == ".text"
        assert pe["signature"]["present"]
        assert not pe["signature"]["verified"]
    elif name == "broken.exe" and result["pe"]["status"] != "unavailable":
        assert result["pe"]["status"] == "error"
    assert result["warnings"]

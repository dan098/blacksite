import csv
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

FIELDS = ["frame.number", "frame.time_relative", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.srcport", "udp.srcport", "tcp.dstport", "udp.dstport", "dns.qry.name", "http.host", "http.request.uri", "tls.handshake.extensions_server_name", "_ws.col.Protocol"]


def summarize(pcap: Path):
    if not pcap.exists():
        return {"status": "unavailable", "detail": "PCAP non presente", "flows": [], "dns": [], "http": []}
    if not shutil.which("tshark") or not shutil.which("bwrap"):
        return {"status": "unavailable", "detail": "tshark e bwrap richiesti", "flows": [], "dns": [], "http": []}
    if pcap.stat().st_size > 1024 * 1024 * 1024:
        return {"status": "error", "detail": "PCAP oltre 1 GB: parser non avviato", "flows": [], "dns": [], "http": []}
    command = ["bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--ro-bind", "/usr", "/usr", "--ro-bind", "/lib", "/lib", "--ro-bind", "/lib64", "/lib64", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/etc", "--ro-bind", str(pcap), "/capture.pcap", "--clearenv", "--setenv", "HOME", "/tmp", "--setenv", "PATH", "/usr/bin", "--", "/usr/bin/prlimit", "--cpu=30", "--as=2147483648", "--fsize=16777216", "--nofile=64", "--", "/usr/bin/tshark", "-n", "-r", "/capture.pcap", "-c", "25000", "-T", "fields", "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=f"]
    for field in FIELDS:
        command += ["-e", field]
    try:
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as error:
            result = subprocess.run(command, stdout=output, stderr=error, timeout=40)
            output.seek(0)
            content = output.read(16 * 1024 * 1024).decode("utf-8", "replace")
            error.seek(0)
            stderr = error.read(2048).decode("utf-8", "replace")
        if result.returncode:
            return {"status": "error", "detail": stderr[:500], "flows": [], "dns": [], "http": []}
        flows = {}
        dns = set()
        http = set()
        packet_count = 0
        for row in csv.reader(content.splitlines(), delimiter="\t"):
            if len(row) != len(FIELDS):
                continue
            packet_count += 1
            src, dst = row[2] or row[3], row[4] or row[5]
            sport, dport = row[6] or row[7], row[8] or row[9]
            proto = row[14]
            key = (src, sport, dst, dport, proto)
            if src and dst and len(flows) < 3000:
                flows[key] = flows.get(key, 0) + 1
            if row[10]:
                dns.add(row[10][:500])
            if row[11] or row[12]:
                http.add((row[11][:500], row[12][:2000]))
        return {"status": "completed", "packets_parsed": packet_count, "truncated": packet_count >= 25000,
                "flows": [{"src": key[0], "src_port": key[1], "dst": key[2], "dst_port": key[3], "protocol": key[4], "packets": count, "attribution": "packet_only"} for key, count in flows.items()],
                "dns": sorted(dns)[:2000], "http": [{"host": host, "uri": uri} for host, uri in sorted(http)[:2000]],
                "detail": "Rete simulata senza internet. PCAP completo separato; pacchetti non automaticamente attribuiti a un PID."}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "error", "detail": str(exc)[:300], "flows": [], "dns": [], "http": []}

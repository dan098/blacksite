"""Real, boot-free public-egress/private-deny check; no host firewall changes."""
import json
from pathlib import Path
import socket
import subprocess
import threading
import uuid

from lab.egress import probe_namespace


def main():
    root = Path(__file__).resolve().parents[1]
    run_dir = root / "data" / "runtime" / ("egress-proof-" + uuid.uuid4().hex)
    addresses = json.loads(subprocess.check_output(["/usr/sbin/ip", "-j", "-4", "addr"], timeout=5))
    host_ips = [item["local"] for link in addresses for item in link.get("addr_info", [])]
    accepted = []
    stop = threading.Event()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as canary:
        canary.bind(("0.0.0.0", 0))
        canary.listen(8)
        canary.settimeout(0.2)
        port = canary.getsockname()[1]

        def serve():
            while not stop.is_set():
                try:
                    connection, address = canary.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                accepted.append(address[0])
                connection.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        denied = list(dict.fromkeys(host_ips + ["127.0.0.1", "10.77.0.2", "10.0.2.2", "10.0.2.3", "10.0.0.1", "172.16.0.1", "192.168.0.1", "169.254.169.254", "100.64.0.1"]))
        targets = [{"address": "1.1.1.1", "port": 443, "allowed": True}]
        targets += [{"address": address, "port": port, "allowed": False} for address in denied]
        try:
            proof = probe_namespace(run_dir, root / "data" / "bases", targets=targets)
        finally:
            stop.set()
            thread.join(timeout=2)
    assert not accepted, "Isolated probe reached host canary"
    assert proof["guest_internet"] is True
    assert proof["guest_lan"] is False and proof["guest_host"] is False
    assert proof["firewall"]["verified"] is True
    result = {"status": "passed", "runtime": str(run_dir), "host_canary_connections": len(accepted), "proof": proof}
    destination = root / "data" / "egress-live-proof.json"
    destination.write_text(json.dumps(result, ensure_ascii=False, indent=2))
    destination.chmod(0o600)
    print(json.dumps({"status": result["status"], "host_canary_connections": len(accepted), "targets": len(targets), "proof": str(destination)}))


if __name__ == "__main__":
    main()

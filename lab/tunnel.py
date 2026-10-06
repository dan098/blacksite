"""Supervise a free HTTPS quick tunnel to the read-only gateway, never the lab API."""
from pathlib import Path
import os
import re
import signal
import subprocess

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'data'
BINARY = DATA / 'tools/cloudflared'
ORIGIN = DATA / 'public-origin'
PATTERN = re.compile(r'https://[a-z0-9]+(?:-[a-z0-9]+)*\.trycloudflare\.com')


def main():
    ORIGIN.write_text('')
    process = subprocess.Popen([str(BINARY), 'tunnel', '--config', '/dev/null', '--no-autoupdate', '--protocol', 'http2',
                                '--url', 'http://127.0.0.1:8766'],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                               env={'PATH':'/usr/bin:/bin', 'HOME': str(DATA / 'tools')})
    def stop(signum, frame):
        process.terminate()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        for line in process.stdout:
            match = PATTERN.search(line)
            if match:
                # A single precreated file is the only writable host mount in this service.
                descriptor = os.open(ORIGIN, os.O_WRONLY | os.O_TRUNC)
                with os.fdopen(descriptor, 'w') as stream:
                    stream.write(match.group() + '\n')
                print('Shared read-only origin: ' + match.group(), flush=True)
            elif 'Registered tunnel connection' in line:
                print('Read-only tunnel connected', flush=True)
            elif 'ERR' in line:
                print(line.strip()[:1000], flush=True)
        return process.wait()
    finally:
        ORIGIN.write_text('')
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == '__main__':
    raise SystemExit(main())

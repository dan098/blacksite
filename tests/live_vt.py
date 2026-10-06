"""Verify the configured VirusTotal key with one known EICAR hash, never a file upload."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re

from lab.static_analysis import _hash_reputation

ROOT = Path(__file__).resolve().parents[1]
EICAR_SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'


def main():
    private = ROOT / 'data/integrations.env'
    if private.is_symlink() or private.stat().st_mode & 0o077:
        raise RuntimeError('Credentials file must be private and not a symlink')
    for line in private.read_text().splitlines():
        name, separator, value = line.partition('=')
        if separator and name in {'VT_API_KEY', 'SANDBOX_VT_HASH_LOOKUP'}:
            os.environ[name] = value
    secret = os.environ.get('VT_API_KEY', '')
    if not re.fullmatch(r'[0-9a-fA-F]{64}', secret):
        raise RuntimeError('Configured VirusTotal key format invalid')
    response = _hash_reputation(EICAR_SHA256)
    proof = {'verified_at': datetime.now(timezone.utc).isoformat(), 'sha256': EICAR_SHA256,
             'request': 'GET /api/v3/files/{sha256}', 'sample_uploaded': False,
             'response': response}
    encoded = json.dumps(proof, ensure_ascii=False, indent=2)
    if secret in encoded:
        raise AssertionError('Credential present in response')
    path = ROOT / 'data/virustotal-live-proof.json'
    path.write_text(encoded)
    print(encoded)
    result = response.get('result', {})
    if response.get('status') != 'completed' or result.get('provider') != 'VirusTotal' or result.get('uploads') is not False:
        raise AssertionError('Authenticated VirusTotal lookup unsuccessful')
    if not result.get('stats') or result['stats'].get('malicious', 0) <= 0:
        raise AssertionError('Known EICAR hash did not produce the expected preexisting reputation')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

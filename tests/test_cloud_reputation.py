import io
import json
from urllib.error import HTTPError

import pytest
from lab import static_analysis


@pytest.mark.parametrize('known', [True, False])
def test_virustotal_existing_or_unknown_hash_never_submits_a_file(monkeypatch, known):
    digest = 'a' * 64
    calls = []
    monkeypatch.setenv('SANDBOX_VT_HASH_LOOKUP', '1')
    monkeypatch.setenv('VT_API_KEY', 'test-only-not-a-real-key')

    class HashOnlyOpener:
        def open(self, request, timeout):
            calls.append(request)
            assert request.get_method() == 'GET'
            assert request.full_url == 'https://www.virustotal.com/api/v3/files/' + digest
            assert request.data is None
            if not known:
                raise HTTPError(request.full_url, 404, 'Not found', {}, None)
            return io.BytesIO(json.dumps({'data': {'attributes': {
                'last_analysis_stats': {'malicious': 1}, 'last_analysis_date': 123
            }}}).encode())

    monkeypatch.setattr(static_analysis, 'build_opener', lambda *args: HashOnlyOpener())
    result = static_analysis._hash_reputation(digest)
    assert result['status'] == 'completed'
    assert result['result']['uploads'] is False
    assert len(calls) == 1
    if not known:
        assert result['result']['known'] is False
        assert 'nessun upload' in result['detail']

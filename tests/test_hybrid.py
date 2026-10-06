import httpx
from lab import hybrid


def test_disabled_provider_never_connects(monkeypatch):
    monkeypatch.delenv("HYBRID_ANALYSIS_API_KEY", raising=False)
    monkeypatch.setattr(httpx, "Client", lambda *a, **kw: (_ for _ in ()).throw(AssertionError("No network")))
    assert hybrid.lookup("a" * 64)["status"] == "disabled"


def test_hash_only_request_and_output_redaction(monkeypatch):
    key = "test-private-provider-key"
    digest = "a" * 64
    monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", key)
    monkeypatch.setenv("SANDBOX_HA_HASH_LOOKUP", "1")
    def handler(request):
        assert request.method == "GET"
        assert request.url.path == "/api/v2/search/hash"
        assert request.headers["api-key"] == key
        assert request.url.params["hash"] == digest
        assert request.content == b""
        return httpx.Response(200, json={"sha256s": [digest], "reports": [{"id": "report-id", "verdict": "malicious", "submit_name": "PRIVATE_NAME", "api-key": key}]})
    original = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs))
    result = hybrid.lookup(digest)
    assert result["status"] == "completed"
    assert result["result"]["uploads"] is False
    assert result["result"]["reports"][0]["scope"] == "external_hash_reputation_not_local_vm"
    assert key not in str(result)
    assert "PRIVATE_NAME" not in str(result)


def test_external_permission_error_not_clean(monkeypatch):
    monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "test-key")
    monkeypatch.setenv("SANDBOX_HA_HASH_LOOKUP", "1")
    original = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: original(transport=httpx.MockTransport(lambda req: httpx.Response(403, text="private-provider-body")), **kwargs))
    result = hybrid.lookup("a" * 64)
    assert result["status"] == "error"
    assert "private-provider-body" not in str(result)

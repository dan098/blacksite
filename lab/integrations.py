"""External integrations are opt-in and never upload sample bytes."""
import os
import re
import httpx


def capabilities():
    elastic = bool(os.environ.get("SANDBOX_ELASTIC_URL") and os.environ.get("SANDBOX_ELASTIC_API_KEY"))
    vt = bool(os.environ.get("VT_API_KEY") and os.environ.get("SANDBOX_VT_HASH_LOOKUP") == "1")
    from lab.hybrid import capabilities as hybrid_capabilities
    return {
        "elastic": {"status": "configured" if elastic else "unavailable", "detail": "Richiede Elasticsearch e un endpoint realmente iscritto; non incluso nella VM base."},
        "virustotal": {"status": "configured" if vt else "disabled", "detail": "Solo reputazione SHA-256, mai upload automatico del sample."},
        "hybrid_analysis": hybrid_capabilities(),
        "dtrace": {"status": "unavailable", "detail": "DTrace kernel non installato. Nt* Frida è tracciamento user-mode, non syscall kernel completa."},
    }


def elastic_lookup(sha256, start, end):
    url = os.environ.get("SANDBOX_ELASTIC_URL", "").rstrip("/")
    key = os.environ.get("SANDBOX_ELASTIC_API_KEY", "")
    host_id = os.environ.get("SANDBOX_ELASTIC_HOST_ID", "")
    if not url or not key:
        return {"status": "unavailable", "verdict": "not_evaluated", "events": [], "detail": "Elastic EDR non configurato/iscritto."}
    if not url.startswith("https://"):
        return {"status": "error", "verdict": "not_evaluated", "events": [], "detail": "Elastic richiede HTTPS con certificato verificabile."}
    if not re.fullmatch(r"[0-9a-f]{64}", sha256 or ""):
        return {"status": "error", "verdict": "not_evaluated", "events": [], "detail": "Hash non valido."}
    filters = [
        {"range": {"@timestamp": {"gte": start, "lte": end}}},
        {"bool": {"should": [{"term": {field: sha256}} for field in ("process.hash.sha256", "file.hash.sha256", "process.Ext.hash.sha256")], "minimum_should_match": 1}},
    ]
    if host_id:
        filters.append({"term": {"host.id": host_id}})
    query = {"size": 1000, "sort": [{"@timestamp": "asc"}], "query": {"bool": {"filter": filters}}, "_source": ["@timestamp", "event", "process", "file.hash", "file.path", "rule", "message", "host.id"]}
    try:
        with httpx.Client(timeout=20, follow_redirects=False, trust_env=False) as client:
            response = client.post(url + "/logs-endpoint.events.*,logs-endpoint.alerts.*/_search", headers={"Authorization": "ApiKey " + key}, json=query)
            response.raise_for_status()
            if len(response.content) > 8 * 1024 * 1024:
                raise ValueError("Elastic response exceeds limit")
            payload = response.json()
        events = [hit.get("_source", {}) for hit in payload.get("hits", {}).get("hits", [])]
        alerts = [event for event in events if event.get("event", {}).get("kind") == "alert"]
        return {"status": "completed", "verdict": ("alert" if alerts else "no_matching_alerts") if host_id else "hash_reputation_only", "events": events,
                "api_events": [event for event in events if event.get("process", {}).get("Ext", {}).get("api")],
                "scope": "enrolled_host" if host_id else "hash_only_not_local_vm_verdict", "truncated": len(events) >= 1000,
                "detail": "Il filtro host.id deve corrispondere alla VM iscritta. Nessun alert non significa innocuo."}
    except (httpx.HTTPError, ValueError) as exc:
        return {"status": "error", "verdict": "not_evaluated", "events": [], "detail": str(exc)[:300]}

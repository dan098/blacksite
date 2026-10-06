"""Hybrid Analysis metadata lookup. Never uploads files or URLs."""
import os
import re
import httpx

BASE = "https://hybrid-analysis.com/api/v2"


def capabilities():
    enabled = os.environ.get("SANDBOX_HA_HASH_LOOKUP") == "1" and bool(os.environ.get("HYBRID_ANALYSIS_API_KEY"))
    return {"status": "configured" if enabled else "disabled", "detail": "Solo reputazione SHA-256 e report già esistenti. Nessun upload automatico; non è il verdetto della VM locale.", "uploads": False}


def headers():
    return {"api-key": os.environ.get("HYBRID_ANALYSIS_API_KEY", ""), "User-Agent": "Falcon Sandbox", "Accept": "application/json"}


def account_status():
    if capabilities()["status"] != "configured":
        return {"status": "disabled"}
    try:
        with httpx.Client(timeout=20, follow_redirects=False, trust_env=False) as client:
            response = client.get(BASE + "/key/current", headers=headers())
        if response.status_code != 200:
            return {"status": "error", "http_status": response.status_code, "detail": "Chiave o permessi Hybrid Analysis non verificati."}
        if len(response.content) > 1024 * 1024:
            return {"status": "error", "detail": "Risposta oltre limite"}
        payload = response.json()
        permitted = {name: payload.get(name) for name in ("is_valid", "is_free", "is_paid", "rate_limits", "privileges") if name in payload}
        return {"status": "available", "account": permitted, "detail": "Autenticazione provider riuscita; autorizzazioni dipendono dal piano.", "uploads": False}
    except (httpx.HTTPError, ValueError):
        return {"status": "error", "detail": "Provider non raggiungibile o risposta non valida; nessun sample inviato."}


def lookup(sha256):
    cap = capabilities()
    if cap["status"] != "configured":
        return {**cap, "result": None}
    if not re.fullmatch(r"[a-f0-9]{64}", sha256 or ""):
        return {"status": "error", "detail": "SHA-256 non valido", "result": None, "uploads": False}
    try:
        with httpx.Client(timeout=25, follow_redirects=False, trust_env=False) as client:
            with client.stream("GET", BASE + "/search/hash", headers=headers(), params={"hash": sha256}) as response:
                if response.status_code != 200:
                    return {"status": "error", "detail": f"Hybrid Analysis HTTP {response.status_code}; autorizzazione, quota o disponibilità del provider.", "result": None, "uploads": False}
                data = bytearray()
                for chunk in response.iter_bytes():
                    data.extend(chunk)
                    if len(data) > 4 * 1024 * 1024:
                        return {"status": "error", "detail": "Risposta Hybrid Analysis oltre limite", "result": None, "uploads": False}
        import json
        payload = json.loads(data)
        records = payload if isinstance(payload, list) else payload.get("reports", payload.get("result", [])) if isinstance(payload, dict) else []
        if isinstance(payload, dict) and "sha256s" in payload and payload["sha256s"] and sha256 not in payload["sha256s"]:
            return {"status": "error", "detail": "Il provider ha restituito hash differenti.", "result": None, "uploads": False}
        fields = ("id", "job_id", "environment_id", "environment_description", "state", "error_type", "error_origin", "analysis_start_time", "sha256", "verdict", "threat_score", "av_detect", "vx_family", "total_signatures")
        reports = []
        for record in records[:100]:
            if not isinstance(record, dict) or record.get("sha256", sha256).lower() != sha256:
                continue
            report = {name: record.get(name) for name in fields if name in record and isinstance(record[name], (str, int, float, bool, type(None)))}
            for name, value in list(report.items()):
                if isinstance(value, str):
                    report[name] = value[:500]
            report["scope"] = "external_hash_reputation_not_local_vm"
            reports.append(report)
        return {"status": "completed", "detail": "Report precedenti per lo stesso hash; nessun risultato non significa file sicuro.", "result": {"reports": reports, "report_count": len(reports), "hash": sha256, "scope": "hash_only", "uploads": False}, "uploads": False}
    except (httpx.HTTPError, ValueError, TypeError, AttributeError):
        return {"status": "error", "detail": "Lookup Hybrid Analysis fallita o risposta non valida; nessun file inviato.", "result": None, "uploads": False}

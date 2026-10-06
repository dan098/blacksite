import json
from pathlib import Path
from fastapi.testclient import TestClient
from lab.api import create_app
from lab.config import ROOT, Settings


def client(tmp_path, max_upload=1000):
    settings = Settings(root=ROOT, data=tmp_path, token="a" * 40, max_upload=max_upload)
    app = create_app(settings, start_worker=False)
    return TestClient(app), app


def auth():
    return {"Authorization": "Bearer " + "a" * 40}


def upload(c, content=b"hello", **data):
    return c.post("/api/jobs", headers=auth(), files={"file": ("a.txt", content)}, data={"static_only": "true", **data})


def test_auth_and_origin(tmp_path):
    c, app = client(tmp_path)
    assert c.get("/api/jobs").status_code == 401
    assert c.get("/api/health").json() == {"status": "ok", "service": "BLACKSITE"}
    assert c.post("/api/session", json={"token": "a" * 40}, headers={"Origin": "http://evil.invalid"}).status_code == 403
    response = c.post("/api/session", json={"token": "a" * 40}, headers={"Origin": "http://testserver"})
    assert response.status_code == 200
    assert "HttpOnly" in response.headers["set-cookie"]
    assert c.get("/api/session").json()["authenticated"]
    assert c.get("/api/jobs").status_code == 200
    assert c.post("/api/jobs/" + "0" * 32 + "/cancel").status_code == 403
    assert "frame-ancestors 'none'" in c.get("/").headers["content-security-policy"]


def test_public_branding_and_local_logo(tmp_path):
    c, app = client(tmp_path)
    assert app.title == "BLACKSITE"
    assert app.version == "0.1.0"
    page = c.get("/")
    assert "<title>BLACKSITE · Detonate. Trace. Contain.</title>" in page.text
    assert 'id="runtime-status-title">Analysis privacy &amp; isolation</h2>' in page.text
    assert "rete offline predefinita, Internet pubblico solo opt-in con host/LAN bloccati." in page.text
    assert "Internet pubblico con host/LAN bloccati." not in page.text
    assert 'src="/static/logo.webp"' in page.text
    assert 'rel="icon" type="image/webp" href="/static/logo.webp"' in page.text
    logo = c.get("/static/logo.webp")
    assert logo.status_code == 200
    assert logo.headers["content-type"] == "image/webp"
    assert "default-src 'self'" in page.headers["content-security-policy"]


def test_runtime_status_exposes_only_analysis_privacy(tmp_path):
    c, _ = client(tmp_path)
    assert c.get("/api/runtime-status").status_code == 401
    response = c.get("/api/runtime-status", headers=auth())
    assert response.status_code == 200
    status = response.json()
    assert set(status) == {"checked_at", "privacy"}
    assert isinstance(status["privacy"], dict)
    capabilities = c.get("/api/capabilities", headers=auth())
    assert capabilities.status_code == 200
    capability_data = capabilities.json()
    assert "privacy" in capability_data
    assert capability_data["network_policy"]["mode"] == (
        "public_ipv4_only" if capability_data["limits"]["internet"] else "offline"
    )


def test_pdf_download_branding(tmp_path):
    c, app = client(tmp_path)
    job_id = upload(c).json()["id"]
    app.state.store.update(job_id, status="completed", summary={}, static={}, runs=[], artifacts=[])
    response = c.get(f"/api/jobs/{job_id}/report.pdf", headers=auth())
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    job = app.state.store.get(job_id)
    assert f'filename="blacksite-{job["sha256"][:12]}.pdf"' in response.headers["content-disposition"]
    assert b"/Title (BLACKSITE analysis report)" in response.content


def test_upload_validation_and_no_paths(tmp_path):
    c, app = client(tmp_path)
    assert upload(c, b"").status_code == 422
    assert upload(c, b"x" * 1001).status_code == 413
    assert upload(c, profiles='["not-a-profile"]').status_code == 422
    assert upload(c, duration="1").status_code == 422
    response = upload(c)
    assert response.status_code == 200
    job_id = response.json()["id"]
    result = c.get("/api/jobs/" + job_id, headers=auth()).json()
    assert "_sample_path" not in json.dumps(result)
    assert result["size"] == 5
    assert (tmp_path / "samples" / (job_id + ".txt")).stat().st_mode & 0o777 == 0o600
    assert c.get("/api/jobs/../api-token", headers=auth()).status_code == 404


def test_share_redaction_revocation_and_download_auth(tmp_path):
    c, app = client(tmp_path)
    job_id = upload(c).json()["id"]
    app.state.store.update(job_id, status="completed", static={"hashes": {"sha256": "abc"}, "strings": ["PRIVATE_SECRET"], "iocs": ["PRIVATE_URL"]}, runs=[{"profile": "standard", "status": "completed", "dynamic": {"events": [{"command_line": "PRIVATE_SECRET"}], "counts": {"related": 1}, "processes": [{"command_line": "PRIVATE_SECRET"}], "capabilities": {}}}])
    link = c.post(f"/api/jobs/{job_id}/share", headers=auth(), json={"hours": 1}).json()["url"]
    token = link.rsplit("/", 1)[1]
    shared = c.get("/api/shared/" + token)
    assert shared.status_code == 200
    assert "PRIVATE" not in shared.text
    assert "a.txt" not in shared.text
    assert c.get(f"/api/jobs/{job_id}/report.pdf").status_code == 401
    assert c.delete(f"/api/jobs/{job_id}/share", headers=auth()).status_code == 200
    assert c.get("/api/shared/" + token).status_code == 404


def test_artifact_cannot_escape_job_dir(tmp_path):
    c, app = client(tmp_path)
    job_id = upload(c).json()["id"]
    secret = tmp_path / "api-token"
    secret.write_text("private")
    app.state.store.update(job_id, artifacts=[{"id": "bad", "_path": str(secret), "name": "secret"}])
    assert c.get(f"/api/jobs/{job_id}/artifacts/bad", headers=auth()).status_code == 404


def test_event_filter_and_cancel(tmp_path):
    c, app = client(tmp_path)
    job_id = upload(c).json()["id"]
    app.state.store.update(job_id, runs=[{"profile": "standard", "status": "completed", "dynamic": {"events": [{"id": "one", "related": True, "category": "registry", "target": "HKCU"}, {"id": "two", "related": False, "category": "file", "target": "noise"}]}}])
    result = c.get(f"/api/jobs/{job_id}/events?related=true", headers=auth()).json()
    assert result["total"] == 1
    assert c.get(f"/api/jobs/{job_id}/events?related=false", headers=auth()).json()["total"] == 2
    assert c.get(f"/api/jobs/{job_id}/events?category=registry&q=HKCU", headers=auth()).json()["total"] == 1
    assert c.post(f"/api/jobs/{job_id}/cancel", headers=auth()).status_code == 200
    assert app.state.store.get(job_id)["cancel_requested"] is True


def test_indexed_events_beyond_initial_view_are_searchable_and_paginated(tmp_path):
    c, app = client(tmp_path)
    job_id = upload(c).json()["id"]
    rows = [{"id": str(n), "related": True, "category": "registry", "target": "late-evidence" if n == 700 else "background"} for n in range(800)]
    app.state.store.replace_events(job_id, "standard", rows)
    app.state.store.update(job_id, runs=[{"profile": "standard", "_events_indexed": True, "status": "completed", "dynamic": {"events": rows}}])
    detail = c.get(f"/api/jobs/{job_id}", headers=auth()).json()
    assert len(detail["runs"][0]["dynamic"]["events"]) == 300
    assert "_events_indexed" not in detail["runs"][0]
    page = c.get(f"/api/jobs/{job_id}/events?offset=650&limit=10", headers=auth()).json()
    assert page["total"] == 800
    assert [x["id"] for x in page["items"]] == [str(n) for n in range(650, 660)]
    late = c.get(f"/api/jobs/{job_id}/events?q=late-evidence", headers=auth()).json()
    assert late["total"] == 1 and late["items"][0]["id"] == "700"

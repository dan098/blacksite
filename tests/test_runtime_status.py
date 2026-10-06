import copy
from datetime import datetime, timezone
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from lab.api import create_app
from lab.config import ROOT, Settings
from lab.public import create_public_app
from lab.runtime_status import privacy_proof_summary, privacy_status, runtime_status


NOW = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)


def valid_proof():
    return {
        "schema_version": 1, "status": "verified", "verified": True,
        "nonce": "a" * 32, "verified_at": "2026-10-05T10:00:00Z",
        "automatic_sample_uploads": False,
        "defender": {
            "MAPSReporting": 0, "SubmitSamplesConsent": 2, "CloudBlockLevel": 0,
            "DisableBlockAtFirstSeen": True, "cloud_block_disabled": True,
            "AMServiceEnabled": True, "AntivirusEnabled": True, "RealTimeProtectionEnabled": True,
            "local_configuration_unchanged": True, "DisableRealtimeMonitoring": False,
            "exclusions_added": False,
        },
        "edge": {
            "verified": True, "browser_closed": True, "profiles_reset": True,
            "auth_state_present": False, "policy_registry_verified": True,
            "runtime_policy_adoption_verified": False,
            "cookie_databases_remaining": 0, "authentication_rows_remaining": 0,
            "identity_stores_remaining": 0,
            "profile_roots": ["profilo controllato"], "audited_roots": ["archivio controllato"],
            "policies": {
                "BrowserSignin": 0, "SyncDisabled": 1, "NonRemovableProfileEnabled": 0,
                "ImplicitSignInEnabled": 0, "WebToBrowserSignInEnabled": 0,
                "StartupBoostEnabled": 0, "BackgroundModeEnabled": 0,
                "MetricsReportingEnabled": 0, "DiagnosticData": 0,
                "SmartScreenEnabled": 0, "SmartScreenPuaEnabled": 0,
                "SendSiteInfoToImproveServices": 0,
            },
        },
        "wer": {"verified": True, "Disabled": 1, "DontSendAdditionalData": 1,
                "automatic_uploads": False,
                "local_dumps": {"DumpType": 1, "DumpCount": 10, "independent_of_reporting": True}},
        "mde": {"verified": True, "onboarded": False, "onboarding_state": 0,
                "onboarding_configuration_present": False, "sense_status": "Stopped"},
        "explorer": {"policy_verified": True, "EnableSmartScreen": 0},
        "tools": {
            "verified": True, "config_readback": True, "automatic_reputation": False,
            "automatic_submission": False,
            "sysinternals": [{"verified": True,
                              "autoruns": {"CheckVirusTotal": 0, "SubmitUnknownImages": 0},
                              "process_explorer": {"VirusTotalCheck": 0, "VirusTotalSubmitUnknown": 0}}],
            "system_informer": [{"verified": True, "online_checks_plugin_disabled": True,
                                 "automatic_reputation": False, "automatic_submission": False}],
        },
    }


def base(proof=None):
    return {"status": "ready", "metadata": {"ready": True, "privacy": valid_proof() if proof is None else proof}}


def test_valid_base_proof_does_not_claim_future_edge_policy_adoption():
    result = privacy_status(base())
    assert result["verified"] is True
    assert result["proof_scope"] == "base"
    assert result["runtime_recheck_required"] is True
    assert result["defender"]["local_active"] is True
    assert result["edge"]["runtime_policy_adoption_verified"] is False
    assert result["external_lookup"]["sample_uploads"] is False
    assert result["external_lookup"]["unknown_hash_uploads"] is False
    value = base()
    original = copy.deepcopy(value)
    privacy_status(value)
    assert value == original


def test_runtime_proof_summary_is_scoped_separately_from_base_readiness():
    summary = privacy_proof_summary(valid_proof(), scope="runtime_pretransfer")
    assert summary["verified"] is True
    assert summary["proof_scope"] == "runtime_pretransfer"
    assert summary["runtime_recheck_required"] is False
    assert summary["edge"]["runtime_policy_adoption_verified"] is False
    assert privacy_proof_summary({}, scope="runtime_pretransfer")["verified"] is False


@pytest.mark.parametrize("path,value", [
    (("verified",), "true"),
    (("automatic_sample_uploads",), True),
    (("defender", "MAPSReporting"), False),
    (("defender", "MAPSReporting"), "0"),
    (("defender", "SubmitSamplesConsent"), 0),
    (("defender", "CloudBlockLevel"), 1),
    (("defender", "RealTimeProtectionEnabled"), False),
    (("edge", "policies", "BrowserSignin"), False),
    (("edge", "policies", "SmartScreenEnabled"), 1),
    (("edge", "auth_state_present"), True),
    (("edge", "cookie_databases_remaining"), 1),
    (("edge", "profile_roots"), []),
    (("wer", "Disabled"), "1"),
    (("mde", "onboarded"), True),
    (("explorer", "EnableSmartScreen"), 1),
    (("tools", "automatic_submission"), True),
    (("tools", "sysinternals"), []),
    (("tools", "sysinternals", 0, "autoruns", "CheckVirusTotal"), False),
    (("tools", "system_informer", 0, "online_checks_plugin_disabled"), False),
    (("schema_version",), True),
])
def test_wrong_metadata_privacy_values_never_turn_green(path, value):
    proof = valid_proof()
    item = proof
    for key in path[:-1]:
        item = item[key]
    item[path[-1]] = value
    result = privacy_status(base(proof))
    assert result["status"] == "unverified"
    assert result["verified"] is False
    assert result["defender"]["local_active"] is None
    assert result["automatic_sample_uploads"] is None


@pytest.mark.parametrize("value", [None, [], {}, {"metadata": []}, {"status": "ready", "metadata": {"privacy": []}}, {"status": "not_ready", "metadata": {"ready": True, "privacy": valid_proof()}}])
def test_missing_or_malformed_base_proof_is_unverified(value):
    assert privacy_status(value)["verified"] is False


def test_runtime_status_is_metadata_only_and_never_reads_files_or_services(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("runtime status must not read files or query services")
    monkeypatch.setattr("pathlib.Path.read_text", forbidden)
    monkeypatch.setattr("pathlib.Path.read_bytes", forbidden)
    monkeypatch.setattr("subprocess.run", forbidden)
    result = runtime_status(base(), now=NOW)
    assert set(result) == {"checked_at", "privacy"}
    assert result["checked_at"] == NOW.isoformat()
    assert result["privacy"]["verified"] is True
    assert result["privacy"]["separation"]["base_state"] == "immutable_separate"


def test_runtime_status_without_base_is_honestly_unverified():
    result = runtime_status({}, now=NOW)
    assert set(result) == {"checked_at", "privacy"}
    assert result["privacy"]["verified"] is False


def test_private_endpoints_require_auth_and_handle_invalid_metadata(tmp_path, monkeypatch):
    calls = []
    def safe_status(value):
        calls.append(value)
        return {"privacy": privacy_status(value), "checked_at": NOW.isoformat()}
    monkeypatch.setattr("lab.api.runtime_status", safe_status)
    monkeypatch.setattr("lab.static_analysis.capabilities", lambda tools: {})
    monkeypatch.setattr("lab.vm.capabilities", lambda directory: {})
    monkeypatch.setattr("lab.api.external_capabilities", lambda: {})
    settings = Settings(root=ROOT, data=tmp_path, token="a" * 40)
    app = create_app(settings, start_worker=False)
    auth = {"Authorization": "Bearer " + "a" * 40}
    with TestClient(app) as client:
        for path in ("/api/runtime-status", "/api/capabilities"):
            assert client.get(path).status_code == 401
        assert calls == []
        for malformed in ("[]", '{"ready":true,"privacy":[]}', "{"):
            (settings.base_dir / "metadata.json").write_text(malformed)
            for path in ("/api/runtime-status", "/api/capabilities"):
                response = client.get(path, headers=auth)
                assert response.status_code == 200
                assert response.json()["privacy"]["verified"] is False
                assert response.headers["cache-control"] == "no-store"
        (settings.base_dir / "metadata.json").write_text(json.dumps({"ready": True, "privacy": valid_proof()}))
        for name in ("clean.qcow2", "OVMF_VARS.fd", "tpm2-00.permall"):
            (settings.base_dir / name).touch()
        assert client.get("/api/runtime-status", headers=auth).json()["privacy"]["verified"] is True
        assert client.get("/api/capabilities", headers=auth).json()["privacy"]["verified"] is True
        assert client.post("/api/runtime-status", headers=auth).status_code == 405
        assert client.get("/api/runtime-status", headers={"Host": "external.invalid", **auth}).status_code == 400


def test_public_gateway_never_exposes_or_proxies_runtime_status():
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"status": "completed", "runs": []})
    with TestClient(create_public_app(httpx.MockTransport(handler))) as client:
        for path in ("/api/runtime-status", "/api/capabilities", "/api/runtime-status?token=" + "a" * 43):
            assert client.get(path, headers={"Authorization": "Bearer PRIVATE"}).status_code == 404
    assert calls == []


def test_shared_report_never_contains_runtime_or_private_privacy_summary(tmp_path, monkeypatch):
    monkeypatch.setattr("lab.api.runtime_status", lambda value: {"privacy": {"verified": False, "PRIVATE": True}})
    settings = Settings(root=ROOT, data=tmp_path, token="a" * 40)
    app = create_app(settings, start_worker=False)
    auth = {"Authorization": "Bearer " + "a" * 40}
    with TestClient(app) as client:
        response = client.post("/api/jobs", headers=auth, files={"file": ("sample.txt", b"hello")}, data={"static_only": "true"})
        assert response.status_code == 200
        job_id = response.json()["id"]
        app.state.store.update(job_id, status="completed", runs=[{"profile": "standard", "status": "completed", "dynamic": {
            "privacy": valid_proof(), "privacy_summary": {"PRIVATE": "account"},
        }}])
        private = client.get(f"/api/jobs/{job_id}", headers=auth).json()
        summary = private["runs"][0]["dynamic"]["privacy_summary"]
        assert summary["verified"] is True
        assert summary["proof_scope"] == "runtime_pretransfer"
        assert "PRIVATE" not in json.dumps(summary)
        link = client.post(f"/api/jobs/{job_id}/share", headers=auth, json={"hours": 1}).json()["url"]
        shared = client.get("/api/shared/" + link.rsplit("/", 1)[1])
        assert shared.status_code == 200
        assert all(key not in shared.text for key in ("privacy_summary", "privacy", "PRIVATE"))
        assert client.get("/api/runtime-status").status_code == 401

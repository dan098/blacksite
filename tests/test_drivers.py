import json
from lab.drivers import enrich


def test_loaded_driver_exact_hash_not_exploit(tmp_path):
    digest = "a" * 64
    (tmp_path / "loldrivers.json").write_text(json.dumps({"records": [{"id": "one", "hashes": {"sha256": digest}, "category": "vulnerable driver"}], "source": "https://www.loldrivers.io/api/drivers.json"}))
    value = enrich({"drivers": [{"id": "sysmon:6", "target": "C:\\test.sys", "details": {"Hashes": "SHA256=" + digest}, "related": False}]}, tmp_path)
    assert value["byovd"]["matches"][0]["evidence"] == "observed_driver_load_exact_hash"
    assert value["findings"][0]["confidence"] == "exact_hash"
    assert not value["findings"][0]["related"]
    assert "non dimostra" in value["findings"][0]["description"]


def test_unavailable_driver_cache(tmp_path):
    assert enrich({}, tmp_path)["byovd"]["status"] == "unavailable"

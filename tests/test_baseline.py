from time import monotonic
from lab.baseline import compare


def snapshot(category, rows, status="completed"):
    return {category: rows, "coverage": {category: {"status": status}}}


def test_registry_casefold_and_value_changes():
    before = snapshot("registry", [{"path": "HKU\\S-1\\Software\\Probe", "view": "Registry64", "name": "Value", "kind": "String", "value_sha256": "a"}])
    after = snapshot("registry", [{"path": "hku\\s-1\\software\\probe", "view": "Registry64", "name": "value", "kind": "String", "value_sha256": "b"}])
    result = compare(before, after)
    assert [r["action"] for r in result["registry"]] == ["modified"]
    assert not result["registry"][0]["related"]


def test_partial_snapshot_does_not_claim_creation_or_deletion():
    before = snapshot("files", [{"path": "C:\\old.txt", "size": 1}], "partial")
    after = snapshot("files", [{"path": "C:\\new.txt", "size": 1}])
    result = compare(before, after)
    assert {r["action"] for r in result["files"]} == {"not_observed_before", "not_observed_after"}
    assert result["coverage"]["files"]["baseline_partial"]


def test_complete_snapshots_have_created_and_deleted():
    result = compare(snapshot("files", [{"path": "C:\\old.txt"}]), snapshot("files", [{"path": "C:\\new.txt"}]))
    assert {r["action"] for r in result["files"]} == {"created", "deleted"}


def test_linear_large_baseline_and_cap():
    rows = [{"path": f"C:\\folder\\{n}.txt", "size": 1} for n in range(50000)]
    start = monotonic()
    assert not compare(snapshot("files", rows), snapshot("files", rows))["files"]
    assert monotonic() - start < 5
    result = compare(snapshot("files", []), snapshot("files", rows), cap=20)
    assert len(result["files"]) == 20
    assert result["coverage"]["files"]["total"] == 50000
    assert result["coverage"]["files"]["truncated"]

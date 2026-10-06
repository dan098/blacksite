from lab.report import render_pdf
from lab.worker import public_job, redacted_share


def test_pdf_escapes_hostile_strings(tmp_path):
    job = {"id": "a" * 32, "name": "<script>alert(1)</script>", "sha256": "b" * 64, "status": "completed", "created_at": "2026-10-01T10:00:00Z", "summary": {}, "static": {"hashes": {"sha256": "b" * 64}, "capabilities": {}}, "runs": [], "artifacts": [], "warnings": ["<&>"]}
    destination = tmp_path / "report.pdf"
    render_pdf(job, destination)
    pdf = destination.read_bytes()
    assert pdf.startswith(b"%PDF-")
    assert b"/Title (BLACKSITE analysis report)" in pdf
    assert b"/Author (BLACKSITE)" in pdf
    assert destination.stat().st_size > 1000


def test_internal_artifact_paths_removed_recursively():
    value = public_job({"_sample_path": "secret", "runs": [{"artifacts": [{"_path": "secret", "id": "one"}]}]})
    assert value == {"runs": [{"artifacts": [{"id": "one"}]}]}

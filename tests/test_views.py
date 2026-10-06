from copy import deepcopy

from lab.views import DISPLAY_CAP, detail_view


def test_detail_prioritizes_sample_and_security_without_changing_full_report():
    background = [{"time": n, "related": False, "category": "file"} for n in range(DISPLAY_CAP + 20)]
    sample = {"time": 999, "related": True, "category": "process", "pid": 42}
    security = {"time": 1000, "related": False, "category": "security"}
    job = {"id": "a" * 32, "runs": [{"dynamic": {"events": background + [sample, security]}}]}
    original = deepcopy(job)
    view = detail_view(job)
    dynamic = view["runs"][0]["dynamic"]
    assert len(dynamic["events"]) == DISPLAY_CAP
    assert dynamic["events"][:2] == [sample, security]
    assert dynamic["display_limits"]["events"]["total"] == DISPLAY_CAP + 22
    assert job == original


def test_snapshot_changes_are_bounded_only_in_initial_view():
    rows = [{"path": f"HKCU\\Software\\Probe{n}"} for n in range(DISPLAY_CAP + 10)]
    job = {"runs": [{"dynamic": {"changes": {"registry": rows, "files": []}}}]}
    view = detail_view(job)["runs"][0]["dynamic"]
    assert len(view["changes"]["registry"]) == DISPLAY_CAP
    assert view["display_limits"]["changes.registry"] == {
        "shown": DISPLAY_CAP,
        "total": DISPLAY_CAP + 10,
        "detail": "Delta completi nel report.json scaricabile.",
    }
    assert len(job["runs"][0]["dynamic"]["changes"]["registry"]) == DISPLAY_CAP + 10


def test_kernel_detail_is_bounded_but_full_original_and_counts_are_preserved():
    rows = [{"id": f"kernel:{n}", "related": False} for n in range(DISPLAY_CAP + 25)]
    related = {"id": "kernel:sample", "related": True}
    maps = {str(n): {"pid": n} for n in range(DISPLAY_CAP + 10)}
    job = {"runs": [{"dynamic": {"kernel": {"events": rows + [related], "syscall_pairs": rows,
                                         "thread_map": maps, "counts": {"events": len(rows) + 1}},
                                "counts": {"kernel_events": len(rows) + 1}}}]}
    original = deepcopy(job)
    view = detail_view(job)["runs"][0]["dynamic"]
    assert len(view["kernel"]["events"]) == DISPLAY_CAP
    assert view["kernel"]["events"][0] == related
    assert len(view["kernel"]["syscall_pairs"]) == DISPLAY_CAP
    assert len(view["kernel"]["thread_map"]) == DISPLAY_CAP
    assert view["kernel"]["counts"]["events"] == len(rows) + 1
    assert view["display_limits"]["kernel.events"]["total"] == len(rows) + 1
    assert job == original


def test_kernel_gaps_are_trimmed_in_both_summary_locations_without_mutation():
    gaps = [{"kind": "missing_enter", "event_id": n} for n in range(DISPLAY_CAP + 15)]
    coverage = {"gaps": gaps, "truncated": True, "full_coverage": False}
    job = {"runs": [{"dynamic": {"kernel": {"coverage": coverage}, "coverage": {"kernel": coverage}}}]}
    original = deepcopy(job)
    view = detail_view(job)["runs"][0]["dynamic"]
    assert len(view["kernel"]["coverage"]["gaps"]) == DISPLAY_CAP
    assert len(view["coverage"]["kernel"]["gaps"]) == DISPLAY_CAP
    assert view["display_limits"]["kernel.coverage.gaps"]["total"] == len(gaps)
    assert view["kernel"]["coverage"]["full_coverage"] is False
    assert job == original

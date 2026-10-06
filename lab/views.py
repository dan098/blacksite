from lab.worker import public_job

DISPLAY_CAP = 300


def compact_job(job, indexed_only=False):
    """Copy bounded summaries, preserving private fields and the full source object."""
    value = dict(job)
    if "runs" not in job:
        return value
    value["runs"] = []
    for source in job.get("runs", []):
        run = dict(source)
        value["runs"].append(run)
        if indexed_only and not run.get("_events_indexed"):
            continue
        dynamic = dict(run.get("dynamic", {}))
        run["dynamic"] = dynamic
        limits = dict(dynamic.get("display_limits", {}))
        for name in ("events", "processes", "registry", "files", "network", "drivers", "api_calls", "call_chains", "syscall_chain", "api_sensor_events"):
            rows = dynamic.get(name)
            if isinstance(rows, list) and len(rows) > DISPLAY_CAP:
                limits[name] = {"shown": DISPLAY_CAP, "total": len(rows), "detail": "Eventi paginati e artefatto report.json contengono tutte le evidenze."}
                # Keep sample evidence and security/driver events visible before background.
                ordered = sorted(rows, key=lambda row: (0 if isinstance(row, dict) and row.get("related") else 1 if isinstance(row, dict) and row.get("category") in {"security", "driver"} else 2))
                dynamic[name] = ordered[:DISPLAY_CAP]
        dynamic["changes"] = dict(dynamic.get("changes", {}))
        for category, rows in dynamic.get("changes", {}).items():
            if isinstance(rows, list) and len(rows) > DISPLAY_CAP:
                limits["changes." + category] = {"shown": DISPLAY_CAP, "total": len(rows), "detail": "Delta completi nel report.json scaricabile."}
                dynamic["changes"][category] = rows[:DISPLAY_CAP]
        kernel = dynamic.get("kernel")
        if isinstance(kernel, dict):
            kernel = dict(kernel)
            dynamic["kernel"] = kernel
            for name in ("events", "syscall_pairs", "stacks", "process_map", "thread_map", "image_map"):
                rows = kernel.get(name)
                if isinstance(rows, list) and len(rows) > DISPLAY_CAP:
                    limits["kernel." + name] = {"shown": DISPLAY_CAP, "total": len(rows), "detail": "Record kernel conservati nel report JSON/ETL; eventi nella timeline paginata. La vista non implica copertura totale."}
                    kernel[name] = sorted(rows, key=lambda row: 0 if isinstance(row, dict) and row.get("related") else 1)[:DISPLAY_CAP]
                elif isinstance(rows, dict) and len(rows) > DISPLAY_CAP:
                    limits["kernel." + name] = {"shown": DISPLAY_CAP, "total": len(rows), "detail": "Mappa completa nel report JSON/ETL."}
                    kernel[name] = dict(list(rows.items())[:DISPLAY_CAP])
            coverage = kernel.get("coverage")
            if isinstance(coverage, dict):
                coverage = dict(coverage)
                kernel["coverage"] = coverage
                gaps = coverage.get("gaps")
                if isinstance(gaps, list) and len(gaps) > DISPLAY_CAP:
                    limits["kernel.coverage.gaps"] = {"shown": DISPLAY_CAP, "total": len(gaps), "detail": "Tutte le lacune misurate nel report JSON; questa vista è limitata."}
                    coverage["gaps"] = gaps[:DISPLAY_CAP]
                dynamic["coverage"] = {**dynamic.get("coverage", {}), "kernel": coverage}
        dynamic["display_limits"] = limits
    return value


def detail_view(job):
    """Initial web view is small; indexed events and raw report remain complete."""
    return public_job(compact_job(job))

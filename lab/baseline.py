"""Compare bounded JSON snapshots in linear time after the VM is stopped.

Snapshot differences are not proof of sample causality. Incomplete snapshots
must never turn missing resources into definite creation or deletion findings.
"""
CATEGORIES = ("registry", "files", "services", "tasks")
FIELDS = {
    "registry": ("kind", "value_sha256"),
    "files": ("kind", "size", "mtime", "creation_time", "attributes"),
    "services": ("Name", "DisplayName", "PathName", "StartMode", "State", "ServiceType", "StartName", "ProcessId"),
    "tasks": ("xml", "error", "truncated"),
}


def key(item, category):
    if category == "registry":
        return (str(item.get("view", "")), str(item.get("path", "")), "key" if item.get("kind") == "key" else "value", str(item.get("name") or ""))
    return (str(item.get("Name", "")) if category == "services" else str(item.get("path", "")),)


def compare(before, after, cap=10000):
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise ValueError("Baseline JSON objects required")
    result = {category: [] for category in CATEGORIES}
    result["coverage"] = {}
    before_coverage = before.get("coverage", {})
    after_coverage = after.get("coverage", {})
    for category in CATEGORIES:
        previous = {tuple(part.casefold() for part in key(item, category)): item for item in before.get(category, []) if isinstance(item, dict)}
        current = {tuple(part.casefold() for part in key(item, category)): item for item in after.get(category, []) if isinstance(item, dict)}
        complete_before = before_coverage.get(category, {}).get("status") == "completed"
        complete_after = after_coverage.get(category, {}).get("status") == "completed"
        incomplete = not complete_before or not complete_after
        rows = result[category]
        total = 0
        def change(action, old, new):
            nonlocal total
            total += 1
            if len(rows) < cap:
                rows.append({"id": f"change:{category}:{total}", "action": action,
                             "path": (new or old or {}).get("path"), "before": old, "after": new,
                             "related": False, "attribution": "snapshot_delta_not_causality", "coverage_partial": incomplete})
        for identity, item in current.items():
            old = previous.get(identity)
            if old is None:
                change("created" if complete_before else "not_observed_before", None, item)
            elif any(str(old.get(field, "")) != str(item.get(field, "")) for field in FIELDS[category]):
                change("modified", old, item)
        for identity, item in previous.items():
            if identity not in current:
                change("not_observed_after" if incomplete else "deleted", item, None)
        result["coverage"][category] = {"total": total, "retained": len(rows), "cap": cap,
                                        "truncated": total > cap, "baseline_partial": incomplete, "comparison": "host_linear_time"}
    return result

#!/usr/bin/env python3
"""
Global Baseline Builder (cross-tenant)

- Input: a folder containing tenant directories.
- Assumed tenant structure:
    <tenants_root>/<tenant_id>/collection/baselines/baseline_latest.json
    <tenants_root>/<tenant_id>/collection/baselines/tenant_abstractions/tenant_abstraction_latest.json

- Output:
    <tenants_root>/global_baselines/global_baseline_latest.json
  (and a timestamped snapshot alongside it)

This script is intentionally "second-order": it never changes tenant baselines.
It aggregates tenant abstractions into a global view you can use for alert de-escalation.
"""
import os
import json
import argparse
from collections import defaultdict
from datetime import datetime
from typing import Dict, Any, Tuple, Optional

# -------------------------
# Tunables (edit as needed)
# -------------------------
TENANT_ABSTRACTION_REL_PATH = os.path.join("collection", "baselines", "tenant_abstractions", "tenant_abstraction_latest.json")
TENANT_BASELINE_REL_PATH    = os.path.join("collection", "baselines", "baseline_latest.json")

GLOBAL_OUT_DIRNAME = "global_baselines"
GLOBAL_LATEST_NAME = "global_baseline_latest.json"

# Cap stored items per field-item map (per global key) to prevent unbounded growth.
CAP_ITEMS_PER_FIELD = 2000

# Keep only top-N file operation entries per global key
CAP_FILE_OP_FILES = 2000

# -------------------------
# Helpers
# -------------------------
def _now_ts() -> str:
    return datetime.utcnow().strftime("%Y%m%d_%H%M%S")

def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_json(obj: Any, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=True)

def _safe_int(x: Any, default: int = 0) -> int:
    try:
        if x is None:
            return default
        return int(x)
    except Exception:
        return default

def _merge_counter_map(dst: Dict[str, int], src: Dict[str, Any], cap: int) -> None:
    """
    Merge {item: count} maps, keeping only top cap by count.
    """
    if not isinstance(src, dict):
        return
    for k, v in src.items():
        dst[k] = _safe_int(dst.get(k, 0)) + _safe_int(v, 0)

    # cap
    if cap and len(dst) > cap:
        # keep top cap by count
        top = sorted(dst.items(), key=lambda kv: kv[1], reverse=True)[:cap]
        dst.clear()
        dst.update(top)

def _merge_set_counter_map(dst: Dict[str, Dict[str, int]], field: str, src_item_counts: Dict[str, Any], cap: int) -> None:
    """
    dst[field] is a dict: {item: total_machine_count_across_tenants}
    """
    if field not in dst:
        dst[field] = {}
    _merge_counter_map(dst[field], src_item_counts, cap)

def _merge_file_ops(dst_file_ops: Dict[str, Any], src_file_ops: Dict[str, Any]) -> None:
    """
    Merge file_operations_frequency blocks.
    Keep file_machine_count and per-operation machine counts.
    """
    if not isinstance(src_file_ops, dict):
        return

    for file_name, fo in src_file_ops.items():
        if file_name not in dst_file_ops:
            dst_file_ops[file_name] = {
                "file_machine_count": 0,
                "operation_machine_counts": {},
            }

        dst = dst_file_ops[file_name]
        dst["file_machine_count"] = _safe_int(dst.get("file_machine_count", 0)) + _safe_int(fo.get("file_machine_count", 0))

        # per operation
        op_counts = fo.get("operation_machine_counts") or {}
        if isinstance(op_counts, dict):
            _merge_counter_map(dst["operation_machine_counts"], op_counts, cap=0)  # don't cap ops within a file

    # cap number of files tracked
    if CAP_FILE_OP_FILES and len(dst_file_ops) > CAP_FILE_OP_FILES:
        top = sorted(dst_file_ops.items(), key=lambda kv: _safe_int(kv[1].get("file_machine_count", 0)), reverse=True)[:CAP_FILE_OP_FILES]
        dst_file_ops.clear()
        dst_file_ops.update(top)

def _tenant_id_from_dir(tenant_dir: str) -> str:
    return os.path.basename(os.path.normpath(tenant_dir))

# -------------------------
# Core aggregation logic
# -------------------------
def merge_tenant_abstraction_into_global(
    global_baseline: Dict[str, Any],
    tenant_abs: Dict[str, Any],
    tenant_id: str,
) -> None:
    """
    global_baseline structure (per key):
      {
        "tenants_seen": [..],
        "tenants_seen_count": int,
        "machines_seen_total": int,
        "users_seen_total": int,
        "occurrence_total": int,
        "last_seen": "...",
        "fields": { field_name: { item: total_machine_count } },
        "file_operations": { file: {...} },
      }
    """
    if not isinstance(tenant_abs, dict):
        return

    now = datetime.utcnow().isoformat() + "Z"

    for tkey, tentry in tenant_abs.items():
        if not isinstance(tentry, dict):
            continue

        g = global_baseline.setdefault(tkey, {
            "tenants_seen": set(),
            "machines_seen_total": 0,
            "users_seen_total": 0,
            "occurrence_total": 0,
            "first_seen": now,
            "last_seen": now,
            "fields": {},
            "file_operations": {},
        })

        # tenants
        g["tenants_seen"].add(tenant_id)

        # counts
        g["machines_seen_total"] += _safe_int(tentry.get("machine_count", 0))
        g["users_seen_total"] += _safe_int(tentry.get("unique_users_count", 0))
        g["occurrence_total"] += _safe_int(tentry.get("occurrence_count", 0))
        g["last_seen"] = now

        # fields: per field, merge item_machine_counts
        fields = tentry.get("fields") or {}
        if isinstance(fields, dict):
            for field_name, fd in fields.items():
                if not isinstance(fd, dict):
                    continue
                item_counts = fd.get("item_machine_counts") or {}
                if isinstance(item_counts, dict):
                    _merge_set_counter_map(g["fields"], field_name, item_counts, cap=CAP_ITEMS_PER_FIELD)

        # file operations
        fo = tentry.get("file_operations_frequency") or {}
        _merge_file_ops(g["file_operations"], fo)

def finalize_global_baseline(global_baseline: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert internal sets -> lists and add derived counts.
    """
    out: Dict[str, Any] = {}
    for k, v in global_baseline.items():
        if not isinstance(v, dict):
            continue
        tenants_set = v.get("tenants_seen", set())
        if isinstance(tenants_set, set):
            tenants_list = sorted(list(tenants_set))
        elif isinstance(tenants_set, list):
            tenants_list = sorted(list(set(tenants_set)))
        else:
            tenants_list = []

        out[k] = {
            "tenants_seen": tenants_list,
            "tenants_seen_count": len(tenants_list),
            "machines_seen_total": _safe_int(v.get("machines_seen_total", 0)),
            "users_seen_total": _safe_int(v.get("users_seen_total", 0)),
            "occurrence_total": _safe_int(v.get("occurrence_total", 0)),
            "first_seen": v.get("first_seen"),
            "last_seen": v.get("last_seen"),
            "fields": v.get("fields") or {},
            "file_operations": v.get("file_operations") or {},
        }
    return out

def load_existing_global(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    raw = load_json(path)
    # convert tenants_seen lists -> sets for internal merging
    merged: Dict[str, Any] = {}
    if isinstance(raw, dict):
        for k, v in raw.items():
            if not isinstance(v, dict):
                continue
            vv = dict(v)
            tenants = vv.get("tenants_seen") or []
            vv["tenants_seen"] = set(tenants) if isinstance(tenants, list) else set()
            merged[k] = vv
    return merged

def process_tenants_root(tenants_root: str, *, use_existing: bool = True) -> Tuple[Dict[str, Any], Dict[str, int]]:
    tenants_root = os.path.abspath(tenants_root)
    out_dir = os.path.join(tenants_root, GLOBAL_OUT_DIRNAME)
    out_latest = os.path.join(out_dir, GLOBAL_LATEST_NAME)

    global_work = load_existing_global(out_latest) if use_existing else {}

    stats = {
        "tenants_total": 0,
        "tenants_used": 0,
        "tenant_abs_missing": 0,
        "tenant_abs_invalid": 0,
        "items_merged": 0,
    }

    for name in sorted(os.listdir(tenants_root)):
        tenant_dir = os.path.join(tenants_root, name)
        if not os.path.isdir(tenant_dir):
            print (f"{tenant_dir} NOT exists")
            continue

        stats["tenants_total"] += 1
        tenant_id = _tenant_id_from_dir(tenant_dir)

        abs_path = os.path.join(tenant_dir, TENANT_ABSTRACTION_REL_PATH)
        if not os.path.exists(abs_path):
            stats["tenant_abs_missing"] += 1
            continue

        try:
            tenant_abs = load_json(abs_path)
        except Exception:
            stats["tenant_abs_invalid"] += 1
            continue

        if not isinstance(tenant_abs, dict):
            stats["tenant_abs_invalid"] += 1
            continue

        before = len(global_work)
        merge_tenant_abstraction_into_global(global_work, tenant_abs, tenant_id)
        after = len(global_work)
        stats["items_merged"] += max(0, after - before)
        stats["tenants_used"] += 1

    # finalize and write
    finalized = finalize_global_baseline(global_work)
    os.makedirs(out_dir, exist_ok=True)
    ts = _now_ts()
    out_snapshot = os.path.join(out_dir, f"global_baseline_{ts}.json")
    save_json(finalized, out_latest)
    save_json(finalized, out_snapshot)
    return finalized, stats

def main():
    ap = argparse.ArgumentParser(description="Build / update cross-tenant global baseline from tenant abstractions.")
    ap.add_argument("tenants_root", help="Folder containing tenant directories.")
    ap.add_argument("--no-incremental", action="store_true", help="Do not merge with existing global_baseline_latest.json; rebuild from scratch.")
    args = ap.parse_args()

    finalized, stats = process_tenants_root(args.tenants_root, use_existing=not args.no_incremental)

    print("Global baseline built.")
    print(json.dumps(stats, indent=2))
    print(f"Global items: {len(finalized)}")

if __name__ == "__main__":
    main()

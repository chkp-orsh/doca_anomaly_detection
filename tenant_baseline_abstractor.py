#!/usr/bin/env python3
import os
import json
from collections import defaultdict
from datetime import datetime
from typing import Dict, Any, Tuple, Optional, Iterable

# =========================
# TUNABLE CONSTANTS
# =========================
# Only create an abstraction group if it appears on at least N machines within the tenant
MIN_MACHINES = 2

# Consensus threshold (fraction of machines in the group that must have seen an item)
# Use this later for "tenant-normal" suppression rather than union
CONSENSUS_THRESHOLD = 0.30

# Memory guard: cap unique items tracked per field (per tenant-group) while building
CAP_TRACK_ITEMS_PER_FIELD = 20000

# Output guard: cap how many items we serialize per field (per tenant-group)
CAP_OUTPUT_ITEMS_PER_FIELD = 5000

# Keep a small obfuscated machine sample in output for sanity/debug
KEEP_MACHINES_SAMPLE = 10

# Output location under each tenant
OUTPUT_SUBDIR_NAME = "tenant_abstractions"

# If you want to ignore some list fields even if they exist, add them here:
IGNORED_LIST_FIELDS = {
    # Example:
    # "detection_reason",  # (usually dict, but just in case)
    "parent_patterns",  # Structured data, not a simple list
    "parent_contexts",
}

# =========================
# PATH CONVENTION
# =========================
BASELINE_REL_PATH = os.path.join("collection", "baselines", "baseline_latest.json")
OUTPUT_REL_DIR = os.path.join("collection", "baselines", OUTPUT_SUBDIR_NAME)


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r") as f:
        return json.load(f)


def save_json(obj: Any, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)


def _is_list_field(v: Any) -> bool:
    return isinstance(v, list)


def _safe_key_old(item: Any) -> Any:
    # Make items hashable for use as dict keys
    if isinstance(item, (list, tuple)):
        return tuple(item)
    return item

def _safe_key(item):
    """Return a stable, hashable representation for use as dict keys.

    IMPORTANT: For primitive items (str/int/float/bool/None) this returns the
    item unchanged, preserving historical output.
    """
    # primitives: keep exactly as-is
    if item is None or isinstance(item, (str, int, float, bool)):
        return item

    # dicts are unhashable -> make deterministic tuple of pairs
    if isinstance(item, dict):
        # sort by key string for determinism (handles mixed key types safely)
        return tuple(
            (_safe_key(k), _safe_key(v))
            for k, v in sorted(item.items(), key=lambda kv: str(kv[0]))
        )

    # lists/tuples/sets -> tuple (recursively)
    if isinstance(item, (list, tuple, set)):
        return tuple(_safe_key(x) for x in item)

    # if it's already hashable, keep it; otherwise fall back to repr
    try:
        hash(item)
        return item
    except TypeError:
        return repr(item)




import msvcrt
def process_single_tenant(tenant_dir: str) -> dict:
    

    print (f"########### tenant_base_line_abstractor: tenant_baseline path: {tenant_dir}" )
    
    #key = msvcrt.getch()
    
    baseline_path = os.path.join(
        tenant_dir, "baselines", "baseline_latest.json"
        )
    print (f"########### tenant_base_line_abstractor: {baseline_path} ")
    if not os.path.exists(baseline_path):
        #raise FileNotFoundError(baseline_path)
        
        baseline_path = os.path.join(
        tenant_dir, "collection","baselines", "baseline_latest.json"
        )
        print (f"########### tenant_base_line_abstractor: switched to {baseline_path}  ")
        if not os.path.exists(baseline_path):
            print (f"########### tenant_base_line_abstractor: failed -  to {baseline_path}  ")
            return NameError
        

    saved_baseline = load_json(baseline_path)

    tenant_abs = build_tenant_abstraction_with_field_frequencies(
        saved_baseline
    )
    if isinstance(tenant_abs, dict):
        print (f"########### tenant_base_line_abstractor:{tenant_dir}, {len(tenant_abs.keys())} items in tenant baseline")

    
    if "collection" in  baseline_path: 
        out_dir = os.path.join(
            tenant_dir, "collection","baselines", "tenant_abstractions"
        )
    else:
            out_dir = os.path.join(
            tenant_dir, "baselines", "tenant_abstractions"
        )
    os.makedirs(out_dir, exist_ok=True)

    out_latest = os.path.join(out_dir, "tenant_abstraction_latest.json")
    save_json(tenant_abs, out_latest)

    return tenant_abs
    


def build_tenant_abstraction_with_field_frequencies(
    saved_baseline: Dict[str, Any],
    *,
    min_machines: int = MIN_MACHINES,
    consensus_threshold: float = CONSENSUS_THRESHOLD,
    cap_track_items_per_field: int = CAP_TRACK_ITEMS_PER_FIELD,
    cap_output_items_per_field: int = CAP_OUTPUT_ITEMS_PER_FIELD,
    keep_machines_sample: int = KEEP_MACHINES_SAMPLE,
) -> Dict[str, Any]:
    """
    Input baseline JSON (per tenant):
      key: "obfMachine||process||normArgs||signer"
      value: baseline payload including list fields like accessed_dirs/contacted_domains/etc.

    Output dict keyed by:
      "process||normArgs||signer"
    containing per-field:
      item_machine_counts, item_coverage, consensus_items
    plus file_operations frequency (per file + per operation).
    """

    first_val = next(iter(saved_baseline.values()), None)
    if not first_val:
        return {}

    # Auto-detect list fields from one record
    list_fields = [
        k for k, v in first_val.items()
        if _is_list_field(v) and k not in IGNORED_LIST_FIELDS
    ]

    # group(tkey) aggregation
    groups = defaultdict(lambda: {
        "_machines": set(),
        "machines_sample": set(),
        "occurrence_count_total": 0,

        # field -> item -> set(machines)
        "list_fields": {f: defaultdict(set) for f in list_fields},

        # file_operations: filename -> set(machines), filename -> op -> set(machines)
        "file_seen": defaultdict(set),
        "file_op_seen": defaultdict(lambda: defaultdict(set)),
    })

    for k, b in saved_baseline.items():
        try:
            obf_machine, process, norm_args, signer = k.split("||", 3)
        except ValueError:
            # Skip unexpected keys
            continue

        tkey = "||".join([process, norm_args, signer])
        g = groups[tkey]

        g["_machines"].add(obf_machine)
        if keep_machines_sample and len(g["machines_sample"]) < keep_machines_sample:
            g["machines_sample"].add(obf_machine)

        g["occurrence_count_total"] += int(b.get("occurrence_count", 0) or 0)

        # Per-list-field frequencies
        for field in list_fields:
            vals = b.get(field, []) or []
            bucket = g["list_fields"][field]

            # cap unique items tracked per field
            if cap_track_items_per_field and len(bucket) >= cap_track_items_per_field:
                # still update already-known items
                for raw in vals:
                    item = _safe_key(raw)
                    if item in bucket:
                        bucket[item].add(obf_machine)
                continue

            for raw in vals:
                item = _safe_key(raw)
                bucket[item].add(obf_machine)

        # file_operations special case
        fo = b.get("file_operations") or {}
        if isinstance(fo, dict):
            for filename, meta in fo.items():
                g["file_seen"][filename].add(obf_machine)
                if isinstance(meta, dict):
                    for op in (meta.get("operations") or []):
                        g["file_op_seen"][filename][op].add(obf_machine)

    # Finalize output
    out: Dict[str, Any] = {}
    for tkey, g in groups.items():
        machine_count = len(g["_machines"])
        if machine_count < min_machines:
            continue

        result = {
            "machine_count": machine_count,
            "machines_sample": list(g["machines_sample"]) if keep_machines_sample else [],
            "occurrence_count_total": g["occurrence_count_total"],
            "consensus_threshold": consensus_threshold,
            "fields": {},
            "file_operations_frequency": {},
        }

        # List fields: counts/coverage/consensus
        for field, item_to_machines in g["list_fields"].items():
            counts = {item: len(ms) for item, ms in item_to_machines.items()}
            coverage = {item: (cnt / machine_count) for item, cnt in counts.items()}

            ranked = sorted(
                counts.keys(),
                key=lambda it: (coverage[it], counts[it], str(it)),
                reverse=True
            )
            if cap_output_items_per_field:
                ranked = ranked[:cap_output_items_per_field]

            consensus = [it for it in ranked if coverage[it] >= consensus_threshold]

            def json_item(x: Any) -> Any:
                return list(x) if isinstance(x, tuple) else x

            # store keys as strings to avoid JSON key issues (esp. tuples)
            result["fields"][field] = {
                "item_machine_counts": {str(json_item(it)): counts[it] for it in ranked},
                "item_coverage": {str(json_item(it)): coverage[it] for it in ranked},
                "consensus_items": [str(json_item(it)) for it in consensus],
            }

        # file_operations frequency: per file + per operation
        file_counts = {fn: len(ms) for fn, ms in g["file_seen"].items()}
        ranked_files = sorted(
            file_counts.keys(),
            key=lambda fn: (file_counts[fn] / machine_count, file_counts[fn], str(fn)),
            reverse=True
        )
        if cap_output_items_per_field:
            ranked_files = ranked_files[:cap_output_items_per_field]

        for fn in ranked_files:
            fn_cnt = file_counts[fn]
            fn_cov = fn_cnt / machine_count
            ops = g["file_op_seen"].get(fn, {})
            op_counts = {op: len(ms) for op, ms in ops.items()}
            op_cov = {op: (c / machine_count) for op, c in op_counts.items()}

            ranked_ops = sorted(
                op_counts.keys(),
                key=lambda op: (op_cov[op], op_counts[op], str(op)),
                reverse=True
            )
            if cap_output_items_per_field:
                ranked_ops = ranked_ops[:cap_output_items_per_field]

            result["file_operations_frequency"][fn] = {
                "file_machine_count": fn_cnt,
                "file_coverage": fn_cov,
                "consensus_file": (fn_cov >= consensus_threshold),
                "operation_machine_counts": {op: op_counts[op] for op in ranked_ops},
                "operation_coverage": {op: op_cov[op] for op in ranked_ops},
                "consensus_operations": [op for op in ranked_ops if op_cov[op] >= consensus_threshold],
            }

        out[tkey] = result

    return out


def iter_tenant_dirs(root_dir: str) -> Iterable[str]:
    # Tenants = immediate subdirectories under root_dir
    for name in os.listdir(root_dir):
        p = os.path.join(root_dir, name)
        if os.path.isdir(p):
            yield p


def process_root(root_dir: str) -> Dict[str, Any]:
    """
    Walk all tenants under root_dir and generate per-tenant abstraction files.
    Returns a small summary dict.
    """
    summary = {
        "root_dir": root_dir,
        "processed_tenants": 0,
        "skipped_no_baseline": 0,
        "errors": 0,
        "tenants": [],  # list of per-tenant summaries
    }

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    for tenant_dir in iter_tenant_dirs(root_dir):
        baseline_path = os.path.join(tenant_dir, BASELINE_REL_PATH)
        if not os.path.exists(baseline_path):
            summary["skipped_no_baseline"] += 1
            continue

        try:
            saved = load_json(baseline_path)
            tenant_abs = build_tenant_abstraction_with_field_frequencies(saved)

            out_dir = os.path.join(tenant_dir, OUTPUT_REL_DIR)
            out_path = os.path.join(out_dir, f"tenant_abstraction_{ts}.json")
            latest_path = os.path.join(out_dir, "tenant_abstraction_latest.json")

            save_json(tenant_abs, out_path)
            save_json(tenant_abs, latest_path)

            summary["processed_tenants"] += 1
            summary["tenants"].append({
                "tenant_dir": tenant_dir,
                "baseline_entries": len(saved),
                "tenant_groups_written": len(tenant_abs),
                "output_latest": latest_path,
            })
        except Exception as e:
            summary["errors"] += 1
            summary["tenants"].append({
                "tenant_dir": tenant_dir,
                "error": repr(e),
            })

    return summary


def main():
    import sys
    if len(sys.argv) != 2:
        print("Usage: python tenant_abstraction_batch.py <root_tenants_folder>")
        sys.exit(2)

    root_dir = sys.argv[1]
    if not os.path.isdir(root_dir):
        print(f"ERROR: Not a directory: {root_dir}")
        sys.exit(2)

    summary = process_root(root_dir)

    # Print a compact summary
    print("\n=== Tenant Abstraction Batch Summary ===")
    print(f"Root: {summary['root_dir']}")
    print(f"Processed tenants: {summary['processed_tenants']}")
    print(f"Skipped (no baseline_latest.json): {summary['skipped_no_baseline']}")
    print(f"Errors: {summary['errors']}")
    print("=======================================")

    # Optional: write a batch summary file under root
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    summary_path = os.path.join(root_dir, f"tenant_abstraction_batch_summary_{ts}.json")
    try:
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"Saved batch summary: {summary_path}")
    except Exception as e:
        print(f"WARNING: could not write summary file: {e!r}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Standalone verification script for LLM-generated Cisco IOS configurations.

Usage:
    # Verify a single task — config as text file (=== CONFIG: xxx === markers)
    python verify.py --metadata-dir metadata/ --task-id task_042 \
        --config-file output/task_042_configs.txt --batfish-host 192.168.31.170

    # Verify a single task — config as snapshot directory (Batfish format)
    python verify.py --metadata-dir metadata/ --task-id task_042 \
        --config-dir output/task_042/configs/ --batfish-host 192.168.31.170

    # Batch verify all outputs in a directory
    python verify.py --metadata-dir metadata/ \
        --output-dir output/ --batfish-host 192.168.31.170

Config input formats:
    1) Text file with markers:
       === CONFIG: AS1_R1 ===
       hostname AS1_R1
       ...
       === END CONFIG ===

    2) Directory of .cfg files (Batfish snapshot):
       configs/
         AS1_R1.cfg
         AS1_R2.cfg
         ...

Output directory structure (for batch mode):
    output/
      task_000/
        configs/          # .cfg files per device (preferred)
        raw_output.txt    # OR text file with markers (fallback)
      task_001/
        ...
"""

import argparse
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, Any
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent))

from verifier import PropertyVerifier, BatfishAdapter
from verifier.schemas import PropertyIR, TopologyContext, VerificationStatus


def parse_configs_from_text(raw_text: str) -> Dict[str, str]:
    """Parse device configs from LLM output using === CONFIG: xxx === markers."""
    configs = {}
    pattern = r'===\s*CONFIG:\s*(\S+)\s*===(.*?)===\s*END\s*CONFIG\s*==='
    for match in re.finditer(pattern, raw_text, re.DOTALL):
        device_name = match.group(1)
        config_text = match.group(2).strip()
        configs[device_name] = config_text
    return configs


def load_configs_from_dir(config_dir: str) -> Dict[str, str]:
    """Load device configs from a directory of .cfg files."""
    configs = {}
    config_path = Path(config_dir)
    for cfg_file in sorted(config_path.glob("*.cfg")):
        device_name = cfg_file.stem
        configs[device_name] = cfg_file.read_text()
    return configs


def prepare_snapshot(configs: Dict[str, str], config_dir: str = None) -> str:
    """Prepare a Batfish snapshot directory.

    If config_dir is provided and already has the right structure, use it directly.
    Otherwise, write configs dict to a temp directory.
    """
    if config_dir:
        config_path = Path(config_dir)
        # Check if it's already a snapshot (has configs/ subdir)
        if (config_path / "configs").is_dir():
            return str(config_path)
        elif any(config_path.glob("*.cfg")):
            # .cfg files directly — wrap in snapshot structure with copy
            snapshot_dir = tempfile.mkdtemp(prefix="bm_snap_")
            dst = os.path.join(snapshot_dir, "configs")
            os.makedirs(dst)
            for cfg in config_path.glob("*.cfg"):
                with open(cfg) as src_f:
                    with open(os.path.join(dst, cfg.name), "w") as dst_f:
                        dst_f.write(src_f.read())
            return snapshot_dir

    # Write from dict
    snapshot_dir = tempfile.mkdtemp(prefix="bm_snap_")
    cfg_dir = os.path.join(snapshot_dir, "configs")
    os.makedirs(cfg_dir, exist_ok=True)
    for device_name, config_text in configs.items():
        with open(os.path.join(cfg_dir, f"{device_name}.cfg"), "w") as f:
            f.write(config_text)
    return snapshot_dir


def load_task_metadata(metadata_dir: str, task_id: str) -> Dict[str, Any]:
    """Load task metadata from metadata/task_xxx.json."""
    meta_path = Path(metadata_dir) / f"{task_id}.json"
    if not meta_path.exists():
        raise FileNotFoundError(f"Metadata not found: {meta_path}")
    with open(meta_path) as f:
        return json.load(f)


def load_all_metadata(metadata_dir: str) -> Dict[str, Dict]:
    """Load all task metadata, indexed by task_id."""
    tasks = {}
    for meta_file in sorted(Path(metadata_dir).glob("task_*.json")):
        with open(meta_file) as f:
            task = json.load(f)
            tasks[task["task_id"]] = task
    return tasks


def verify_single(
    task: Dict[str, Any],
    configs: Dict[str, str],
    batfish_host: str,
    verbose: bool = True,
    config_dir: str = None,
) -> Dict[str, Any]:
    """Verify configs against a single task's properties."""
    task_id = task["task_id"]
    topo_ctx_raw = task["topo_ctx"]
    properties = task["properties"]

    topo_ctx = TopologyContext.from_dict(topo_ctx_raw)
    prop_irs = [PropertyIR.from_dict(p) if isinstance(p, dict) else p for p in properties]

    snapshot_dir = prepare_snapshot(configs, config_dir)

    adapter = BatfishAdapter(host=batfish_host)
    adapter.connect()
    snapshot_name = f"bm_{task_id}_{int(time.time())}"
    adapter.init_snapshot(snapshot_path=snapshot_dir, snapshot_name=snapshot_name)

    verifier = PropertyVerifier(adapter)
    results = [verifier.verify_property(p, topo_ctx) for p in prop_irs]
    conn_dict = verifier.verify_connectivity(topo_ctx)

    conn_pass = conn_dict.get("connectivity_pass", False)
    conn_issues = conn_dict.get("issues", [])

    # Summarize
    prop_results = []
    for prop_ir, result in zip(prop_irs, results):
        entry = {
            "property_id": prop_ir.id,
            "type": prop_ir.type.value if hasattr(prop_ir.type, 'value') else str(prop_ir.type),
            "status": result.status.value,
        }
        if result.counterexample:
            entry["counterexample"] = result.counterexample.description
            entry["details"] = result.counterexample.details
        if result.repair_hint:
            entry["repair_hint"] = result.repair_hint
        prop_results.append(entry)

    num_pass = sum(1 for r in results if r.status == VerificationStatus.PASS)
    num_fail = sum(1 for r in results if r.status == VerificationStatus.FAIL)
    num_error = sum(1 for r in results if r.status == VerificationStatus.ERROR)

    ebgp = conn_dict.get("ebgp_sessions", {})
    ibgp = conn_dict.get("ibgp_sessions", {})
    reach = conn_dict.get("reachability_checks", {})

    summary = {
        "task_id": task_id,
        "topo_id": task.get("topo_id"),
        "difficulty": task.get("difficulty"),
        "num_devices_expected": len(topo_ctx_raw.get("nodes", [])),
        "num_devices_generated": len(configs),
        "connectivity": {
            "pass": conn_pass,
            "ebgp": f"{ebgp.get('established', 0)}/{ebgp.get('expected', 0)}",
            "ibgp": f"{ibgp.get('established', 0)}/{ibgp.get('total', 0)}",
            "reachability": f"{reach.get('passed', 0)}/{reach.get('total', 0)}",
            "issues": [i["description"] for i in conn_issues[:5]],
        },
        "properties_total": len(properties),
        "properties_pass": num_pass,
        "properties_fail": num_fail,
        "properties_error": num_error,
        "all_pass": num_pass == len(properties) and conn_pass,
        "property_results": prop_results,
    }

    if verbose:
        conn_icon = "PASS" if conn_pass else "FAIL"
        print(f"  [{conn_icon}] Connectivity (eBGP {ebgp.get('established',0)}/{ebgp.get('expected',0)}, "
              f"iBGP {ibgp.get('established',0)}/{ibgp.get('total',0)}, "
              f"reachability {reach.get('passed',0)}/{reach.get('total',0)})")
        if conn_issues:
            for issue in conn_issues[:3]:
                print(f"         {issue['description'][:120]}")
        for prop_ir, result in zip(prop_irs, results):
            s = {VerificationStatus.PASS: "PASS", VerificationStatus.FAIL: "FAIL", VerificationStatus.ERROR: "ERR "}.get(result.status, "????")
            ptype = prop_ir.type.value if hasattr(prop_ir.type, 'value') else str(prop_ir.type)
            print(f"  [{s}] {prop_ir.id} ({ptype})")
            if result.counterexample:
                print(f"         {result.counterexample.description[:120]}")

    return summary


def _resolve_task_configs(task_dir: Path):
    """Resolve configs from a task output directory.

    Priority:
      1) configs/ subdirectory with .cfg files
      2) raw_output.txt with === CONFIG === markers

    Returns (configs_dict, config_dir_or_none)
    """
    configs_subdir = task_dir / "configs"
    if configs_subdir.is_dir() and any(configs_subdir.glob("*.cfg")):
        configs = load_configs_from_dir(str(configs_subdir))
        return configs, str(configs_subdir)

    raw_file = task_dir / "raw_output.txt"
    if raw_file.exists():
        configs = parse_configs_from_text(raw_file.read_text())
        return configs, None

    return {}, None


def main():
    parser = argparse.ArgumentParser(
        description="Verify LLM-generated Cisco IOS configurations against task requirements"
    )
    parser.add_argument(
        "--metadata-dir", required=True,
        help="Path to metadata/ directory containing task_xxx.json files"
    )
    parser.add_argument(
        "--batfish-host", default="192.168.31.170",
        help="Batfish server host (default: 192.168.31.170)"
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--config-file",
        help="Single text file with === CONFIG === markers (use with --task-id)"
    )
    group.add_argument(
        "--config-dir",
        help="Directory of .cfg files, Batfish snapshot format (use with --task-id)"
    )
    group.add_argument(
        "--output-dir",
        help="Batch mode: directory with per-task subdirs (configs/ or raw_output.txt)"
    )

    parser.add_argument("--task-id", help="Task ID (required for single-task mode)")
    parser.add_argument("--result-file", default="verification_results.jsonl",
                       help="Output JSONL for batch results (default: verification_results.jsonl)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Minimal output")

    args = parser.parse_args()

    # --- Single task mode ---
    if args.config_file or args.config_dir:
        if not args.task_id:
            parser.error("--task-id is required with --config-file / --config-dir")

        task = load_task_metadata(args.metadata_dir, args.task_id)

        if args.config_dir:
            configs = load_configs_from_dir(args.config_dir)
            config_dir = args.config_dir
        else:
            with open(args.config_file) as f:
                configs = parse_configs_from_text(f.read())
            config_dir = None

        if not configs:
            print(f"Error: no configs found")
            sys.exit(1)

        print(f"Task: {args.task_id} ({len(configs)} devices)")
        result = verify_single(task, configs, args.batfish_host,
                              verbose=not args.quiet, config_dir=config_dir)
        print(f"\nResult: {'ALL PASS' if result['all_pass'] else 'FAIL'} "
              f"({result['properties_pass']}/{result['properties_total']} properties)")
        return

    # --- Batch mode ---
    all_tasks = load_all_metadata(args.metadata_dir)
    output_dir = Path(args.output_dir)
    all_results = []
    stats = defaultdict(int)

    task_dirs = sorted([d for d in output_dir.iterdir() if d.is_dir()])
    print(f"Found {len(task_dirs)} subdirectories in {output_dir}")
    print()

    for task_dir in task_dirs:
        task_id_match = re.search(r'(task_\d+)', task_dir.name)
        if not task_id_match:
            continue
        task_id = task_id_match.group(1)

        if task_id not in all_tasks:
            print(f"  Skip {task_dir.name}: task_id '{task_id}' not in metadata")
            continue

        configs, config_dir = _resolve_task_configs(task_dir)

        if not configs:
            print(f"  {task_id}: no configs found, skipping")
            stats["parse_error"] += 1
            all_results.append({"task_id": task_id, "error": "no configs found", "all_pass": False})
            continue

        src = "configs/" if config_dir else "raw_output.txt"
        print(f"  {task_id} ({len(configs)} devices, from {src})...")
        try:
            result = verify_single(
                all_tasks[task_id], configs, args.batfish_host,
                verbose=not args.quiet, config_dir=config_dir
            )
            all_results.append(result)
            stats["pass" if result["all_pass"] else "fail"] += 1
        except Exception as e:
            print(f"    ERROR: {e}")
            stats["error"] += 1
            all_results.append({"task_id": task_id, "error": str(e), "all_pass": False})
        print()

    # Write results
    with open(args.result_file, "w") as f:
        for r in all_results:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    total = len(all_results)
    print("=" * 60)
    print(f"Verification Summary")
    print(f"  Total:       {total}")
    print(f"  All Pass:    {stats['pass']}")
    print(f"  Fail:        {stats['fail']}")
    print(f"  Error:       {stats['error']}")
    print(f"  Parse Error: {stats['parse_error']}")
    if total > 0:
        print(f"  Pass Rate:   {stats['pass']/total*100:.1f}%")
    print(f"\nResults written to: {args.result_file}")


if __name__ == "__main__":
    main()

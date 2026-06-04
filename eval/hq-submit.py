#!/usr/bin/env python3
import argparse
import base64
import csv
import hashlib
import json
import random
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

def variant_to_args(variant: str) -> tuple[str, str, str]:
    """Return (bucket_suffix, experiment_arg, env_assignments)."""
    if variant == "default":
        return ("default", "", "")
    # any other value is treated as a bare --experiment=<value>
    return (variant, f"--experiment={variant}", "")

def cas_copy_target(target: Path, cas_dir: Path, short_hash_len: int = 4) -> Path:
    with open(target, "rb") as f:
        digest = hashlib.file_digest(f, hashlib.blake2b)
    digest_b64 = base64.urlsafe_b64encode(digest.digest()).decode("ascii").rstrip("=").replace("_", "").replace("-", "")
    path = cas_dir / f"{target.stem}-{digest_b64[:short_hash_len]}{target.suffix}"
    if not path.exists():
        shutil.copy2(target, path)
    return path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--harness-suite", default="./harness-suite/out")
    ap.add_argument("--tags-csv", default="./harness-suite/tags.csv")
    ap.add_argument("--target", action="append", default=[])
    ap.add_argument("--tag", action="append", default=[])
    ap.add_argument("--skip-tag", action="append", default=[])
    ap.add_argument("--variant", action="append", default=None,
                    help="Repeatable. e.g. 'default', 'snapshot'.")
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--hq-dir", default="~/hq")
    ap.add_argument("--fuzzer", default="./target/release/wasmfuzz", help="Fuzzer path")
    ap.add_argument("--monitor", default="~/.cargo/bin/wasmfuzz", help="Monitor path")
    ap.add_argument("--timeout", default="1h", help="Length of each task")
    ap.add_argument("--monitor-interval", default="5m", help="monitor-cov sampling interval")
    ap.add_argument("--corpora-dir", default="", help="Optional output directory for corpora")
    ap.add_argument("--runner", default="./eval/hq-run-one.py", help="Runner script")
    ap.add_argument("--submit-cwd", default="/tmp", help="Working directory for 'hq submit'")
    args = ap.parse_args()

    variants = args.variant or ["default"]

    suite_dir = Path(args.harness_suite)
    assert suite_dir.is_dir(), f"--harness-suite={suite_dir} not found"

    tags = defaultdict(set)
    tags_path = Path(args.tags_csv)
    if tags_path.exists():
        with open(tags_path) as f:
            for row in csv.DictReader(f):
                harness = Path(row["harness"]).stem
                for k, v in row.items():
                    if v in {"1", "true"}:
                        tags[harness].add(k)
    elif args.tag or args.skip_tag:
        print(f"[ERR] --tag/--skip-tag set but {tags_path} not found",
              file=sys.stderr)
        sys.exit(1)

    targets = []
    for t in sorted(suite_dir.glob("*.wasm")):
        if args.target and not any(s in t.stem for s in args.target):
            continue
        if args.tag and not all(x in tags[t.stem] for x in args.tag):
            continue
        if any(x in tags[t.stem] for x in args.skip_tag):
            continue
        targets.append(t)

    hq_dir = Path(args.hq_dir).expanduser()
    runs_dir = hq_dir / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    cas_dir = hq_dir / "cas"
    cas_dir.mkdir(parents=True, exist_ok=True)
    cas_targets = {target: cas_copy_target(target, cas_dir) for target in targets}
    cas_fuzzer = cas_copy_target(Path(args.fuzzer).expanduser(), cas_dir)
    cas_monitor = cas_copy_target(Path(args.monitor).expanduser(), cas_dir)
    cas_runner = cas_copy_target(Path(args.runner).expanduser(), cas_dir)
    fuzzer_id = cas_fuzzer.stem.split("-")[-1]

    tasks = []
    for _ in range(args.repeat):
        for target in targets:
            for variant in variants:
                bucket_suffix, exp_arg, env_assigns = variant_to_args(variant)
                tasks.append({
                    "fuzzer": str(cas_fuzzer),
                    "monitor": str(cas_monitor),
                    "target": str(cas_targets[target]),
                    "runs_dir": str(runs_dir),
                    "bucket": f"{fuzzer_id}-{bucket_suffix}",
                    "timeout": args.timeout,
                    "monitor_interval": args.monitor_interval,
                    "corpora_dir": args.corpora_dir,
                    "experiment_arg": exp_arg,
                    "env_assignments": env_assigns,
                })
    random.shuffle(tasks)

    with tempfile.NamedTemporaryFile(prefix="wasmfuzz-hq-submit-", suffix=".json", mode="w") as tmp_fh:
        json.dump(tasks, tmp_fh)
        tmp_fh.flush()
        print(f"Submitting {len(tasks)} tasks ...", file=sys.stderr)
        subprocess.run([
            hq_dir / 'hq', 'submit',
            '--from-json', tmp_fh.name,
            '--task-dir',
            '--time-request', args.timeout,
            '--name', f"{cas_fuzzer.stem}-{'-'.join(variants)}",
            str(cas_runner)],
            cwd=Path(args.submit_cwd).expanduser())


if __name__ == "__main__":
    main()

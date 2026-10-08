#!/usr/bin/env python3
import argparse
import base64
import csv
import hashlib
import json
import itertools
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
    ap.add_argument("--fuzzer", action="append", default=None,
                    help="Fuzzer path (default ./target/release/wasmfuzz); repeat to interleave several "
                         "binaries in one job, so their arms share nodes and NUMA placement")
    ap.add_argument("--monitor", default="~/.cargo/bin/wasmfuzz", help="Monitor path")
    ap.add_argument("--timeout", default="1h", help="Length of each task")
    ap.add_argument("--monitor-interval", default="5m", help="monitor-cov sampling interval")
    ap.add_argument("--corpora-dir", default="", help="Optional output directory for corpora")
    ap.add_argument("--crash-corpora-dir", default="",
                    help="Optional output directory for corpora of runs that exited early (crashes)")
    ap.add_argument("--runner", default="./eval/hq-run-one.py", help="Runner script")
    ap.add_argument("--cpus", type=int, default=1,
                    help="Cores per task (the runner passes them to `wasmfuzz fuzz --cores`)")
    ap.add_argument("--env", action="append", default=[],
                    help="KEY=VALUE set for every task (e.g. WASMFUZZ_LOD=html); repeatable")
    ap.add_argument("--arm-tag", default="",
                    help="suffix for every bucket (arm name), e.g. to tell an --env arm from the plain one")
    ap.add_argument("--submit-cwd", default="/tmp", help="Working directory for 'hq submit'")
    ap.add_argument("--priority", type=int, default=0,
                    help="hq task priority; negative lets other queued jobs take freed cores first")
    args = ap.parse_args()
    if args.cpus < 1:
        ap.error("--cpus must be positive")

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
    all_stems = {t.stem for t in suite_dir.glob("*.wasm")}
    # Exact harness names match only themselves; other filters match substrings.
    def target_match(stem: str) -> bool:
        return any(s == stem if s in all_stems else s in stem for s in args.target)
    for t in sorted(suite_dir.glob("*.wasm")):
        if args.target and not target_match(t.stem):
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
    cas_fuzzers = [cas_copy_target(Path(f).expanduser(), cas_dir)
                   for f in (args.fuzzer or ["./target/release/wasmfuzz"])]
    cas_monitor = cas_copy_target(Path(args.monitor).expanduser(), cas_dir)
    cas_runner = cas_copy_target(Path(args.runner).expanduser(), cas_dir)

    tasks = []
    for _ in range(args.repeat):
        for target in targets:
            for cas_fuzzer, variant in itertools.product(cas_fuzzers, variants):
                fuzzer_id = cas_fuzzer.stem.split("-")[-1]
                bucket_suffix, exp_arg, env_assigns = variant_to_args(variant)
                if args.arm_tag:
                    bucket_suffix += f"-{args.arm_tag}"
                tasks.append({
                    "fuzzer": str(cas_fuzzer),
                    "monitor": str(cas_monitor),
                    "target": str(cas_targets[target]),
                    "runs_dir": str(runs_dir),
                    "bucket": f"{fuzzer_id}-{bucket_suffix}" + (f"-c{args.cpus}" if args.cpus > 1 else ""),
                    "timeout": args.timeout,
                    "monitor_interval": args.monitor_interval,
                    "corpora_dir": args.corpora_dir,
                    "crash_corpora_dir": args.crash_corpora_dir,
                    "experiment_arg": exp_arg,
                    "env_assignments": " ".join(filter(None, [env_assigns, *args.env])),
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
            '--cpus', str(args.cpus),
            f'--priority={args.priority}',  # '=': hq reads a bare negative value as a flag
            '--name', f"{'+'.join(f.stem for f in cas_fuzzers)}-{'-'.join(variants)}",
            str(cas_runner)],
            cwd=Path(args.submit_cwd).expanduser())


if __name__ == "__main__":
    main()

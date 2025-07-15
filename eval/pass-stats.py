#!/usr/bin/env python3

from subprocess import check_output
from pathlib import Path
import concurrent.futures
import os
import argparse
import json

parser = argparse.ArgumentParser()
parser.add_argument('--wasmfuzz', default="wasmfuzz")
parser.add_argument('--perf-dir', default="/tmp/pass-stats/perf")
parser.add_argument('--corr-dir', default="/tmp/pass-stats/corr")
parser.add_argument('--harness-suite', default="./harness-suite/")
parser.add_argument('--tags-json', default="./harness-suite/tags.json")

args = parser.parse_args()

perf_dir = Path(args.perf_dir)
corr_dir = Path(args.corr_dir)
corpus_dir = Path(args.harness_suite) / "corpus"
harness_dir = Path(args.harness_suite) / "out"
perf_dir.mkdir(parents=True, exist_ok=True)
corr_dir.mkdir(parents=True, exist_ok=True)

with open(args.tags_json) as f:
    tags = json.load(f)

if __name__ == "__main__":
    cmds = []
    for corpus_dir in corpus_dir.glob("*"):
        target = corpus_dir.parts[-1]
        target_tags = tags[target + ".wasm"]
        if "suite" not in target_tags:
            print(f"Skipping {target}: not tagged as suite")
            continue
        bin_path = harness_dir / (target + ".wasm")
        if not bin_path.exists():
            print(f"Skipping {target} because {bin_path} does not exist")
            continue
        csvs = list(corpus_dir.glob("*.csv"))
        if len(csvs) == 0:
            print(f"Skipping {target} because {corpus_dir} is empty")
            continue
        csvs.sort(key=lambda x: x.stem)
        corpus_dir = corpus_dir / csvs[-1].stem
        if not (perf_dir / f"{target}.jsonl").exists():
            cmds.append([args.wasmfuzz, "eval-pass-speed", "--jsonl-out-path", perf_dir / f"{target}.jsonl", bin_path, corpus_dir])
        if not (corr_dir / f"{target}.jsonl").exists():
            cmds.append([args.wasmfuzz, "eval-pass-corr", "--jsonl-out-path", corr_dir / f"{target}.jsonl", bin_path, corpus_dir])


    def run_cmd(cmd):
        cmd = [str(c) for c in cmd]
        print(' '.join(cmd))
        return check_output(cmd)

    max_workers = int(os.cpu_count() * 0.9)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(run_cmd, cmd) for cmd in cmds]
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"Command failed: {e}")

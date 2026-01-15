#!/usr/bin/env python3

import argparse
import csv
import subprocess
import shutil
from pathlib import Path
from typing import Literal


parser = argparse.ArgumentParser()
parser.add_argument("--wasmfuzz", default="wasmfuzz")
parser.add_argument("--harness-dir", default="./out")
parser.add_argument("--corpus-dir", default="./corpus")
parser.add_argument("--crashes-dir", default="./crashes")
parser.add_argument("--ooms-dir", default="./ooms")
parser.add_argument("--timeouts-dir", default="./timeouts")
parser.add_argument("--tags", default="./tags.csv")
parser.add_argument("--only-target", default=None)
parser.add_argument("--mode", default="crash")

args = parser.parse_args()
harness_dir = Path(args.harness_dir)
corpus_dir = Path(args.corpus_dir)
crashes_dir = Path(args.crashes_dir)
ooms_dir = Path(args.ooms_dir)
timeouts_dir = Path(args.timeouts_dir)
tags_path = Path(args.tags)
mode = args.mode
# Literal["crash"] | Literal["oom"] | Literal["timeout"]
assert mode in ["crash", "oom", "timeout"]
mode_path = {"crash": crashes_dir, "oom": ooms_dir, "timeout": timeouts_dir}[mode]
mode_path.mkdir(exist_ok=True)
csv_key = {"crash": "crashed", "timeout": "timeout", "oom": "oom"}[mode]

assert all(x.exists() for x in [harness_dir, mode_path, tags_path])
if not corpus_dir.exists():
    print("[!] corpus directory not found, can't cross-check")


def check_reproduces(harness_path, crash_path, mode="crash"):
    print(f"[*] reproducing {crash_path} ...")
    res = subprocess.check_output(
        [args.wasmfuzz, "run-input", harness_path, crash_path]
    )
    print("[>]", res.decode("utf8", errors="ignore").splitlines()[-1].strip())
    if mode == "crash":
        return (
            b"execution trapped with" in res
            and b"which indicates that the target crashed" in res
        )
    if mode == "oom":
        raise RuntimeError("TODO")
    if mode == "timeout":
        return b"execution stopped with OutOfFuel" in res


harness_paths = sorted(list(harness_dir.glob("*.wasm")))

verified = set()


def check_harness(harness_path):
    harness = harness_path.name
    crash_path = mode_path / f"{harness_path.stem}.bin"
    if crash_path.exists():
        if check_reproduces(harness_path, crash_path, mode=mode):
            verified.add(harness)
            return

    if not corpus_dir.exists():
        return
    for corpus_snapshot in corpus_dir.glob(f"{harness_path.stem}/snapshot-*.csv"):
        with open(corpus_snapshot) as f:
            for elem in csv.DictReader(f):
                if elem[csv_key] and int(elem[csv_key]):
                    input_path = (
                        corpus_snapshot.parent / corpus_snapshot.stem / elem["input"]
                    )
                    assert check_reproduces(harness_path, input_path, mode=mode)
                    verified.add(harness)
                    shutil.copy(input_path, crash_path)
                    return


for harness_path in harness_paths:
    if args.only_target is not None and args.only_target not in harness_path.name:
        continue
    check_harness(harness_path)

mismatches = set()
if mode == "crash":
    with open(tags_path) as f:
        for row in csv.DictReader(f):
            harness = Path(row["harness"]).name
            if args.only_target is not None and args.only_target not in harness:
                continue
            tagged_crash = row["crashing"] and bool(int(row["crashing"]))
            if tagged_crash != (harness in verified):
                mismatches.add(harness)

for input_path in mode_path.glob("*.bin"):
    if args.only_target is not None and args.only_target not in input_path.stem:
        continue
    harness = input_path.stem
    harness_path = harness_dir / f"{harness}.wasm"
    if not harness_path.exists():
        print(f"[!] {harness}: Missing harness!")

print()
print("-" * 80)
print(f"{len(mismatches)} mismatches found" + ".:"[bool(mismatches)])
with open(tags_path) as f:
    for row in csv.DictReader(f):
        harness = Path(row["harness"])
        if args.only_target is not None and args.only_target not in harness.name:
            continue
        input_path = mode_path / f"{harness.stem}.bin"
        tagged_crash = row["crashing"] and bool(int(row["crashing"]))
        if tagged_crash and harness.name not in verified:
            if input_path.exists():
                print(f"[!] {harness.name}: Input for tagged crash didn't reproduce!")
            else:
                print(f"[!] {harness.name}: Missing reproducer for tagged harness!")
        if input_path.exists() and not tagged_crash:
            if harness.name in verified:
                print(f"[!] {harness.name}: Crash reproduced but not tagged!")
            else:
                print(f"[!] {input_path} exists but doesn't reproduce!")

#!/usr/bin/env python3

import argparse
import csv
import subprocess
import shutil
from pathlib import Path


parser = argparse.ArgumentParser()
parser.add_argument('--wasmfuzz', default="wasmfuzz")
parser.add_argument('--harness-dir', default="./out")
parser.add_argument('--corpus-dir', default="./corpus")
parser.add_argument('--crashes-dir', default="./crashes")
parser.add_argument('--tags', default="./tags.csv")

args = parser.parse_args()
harness_dir = Path(args.harness_dir)
corpus_dir = Path(args.corpus_dir)
crashes_dir = Path(args.crashes_dir)
tags_path = Path(args.tags)
assert all(x.exists() for x in [harness_dir, corpus_dir, crashes_dir, tags_path])

def check_reproduces(harness_path, crash_path):
    print(f"[*] reproducing {crash_path} ...")
    res = subprocess.check_output([
        args.wasmfuzz,
        "run-input",
        harness_path,
        crash_path
    ])
    print("[>]", res.decode('utf8', errors='ignore').splitlines()[-1].strip())
    if b"execution trapped with" in res and b"which indicates that the target crashed" in res:
        return True

harness_paths = sorted(list(harness_dir.glob("*.wasm")))

verified = set()

def check_harness(harness_path):
    harness = harness_path.name
    crash_path = crashes_dir / f"{harness_path.stem}.bin"
    if crash_path.exists():
        if check_reproduces(harness_path, crash_path):
            verified.add(harness)
            return

    for corpus_snapshot in corpus_dir.glob(f"{harness_path.stem}/snapshot-*.csv"):
        with open(corpus_snapshot) as f:
            for elem in csv.DictReader(f):
                if elem["crashed"] and int(elem["crashed"]):
                    input_path = corpus_snapshot.parent / corpus_snapshot.stem / elem["input"]
                    assert check_reproduces(harness_path, input_path)
                    verified.add(harness)
                    shutil.copy(input_path, crash_path)
                    return

for harness_path in harness_paths:
    check_harness(harness_path)

mismatches = set()
with open(tags_path) as f:
    for row in csv.DictReader(f):
        harness = Path(row["harness"]).name
        tagged_crash = row["crashing"] and bool(int(row["crashing"]))
        if tagged_crash != (harness in verified):
            mismatches.add(harness)

print()
print("-"*80)
print(f"{len(mismatches)} mismatches found" + ".:"[bool(mismatches)])
with open(tags_path) as f:
    for row in csv.DictReader(f):
        harness = Path(row["harness"])
        crash_path = crashes_dir / f"{harness.stem}.bin"
        tagged_crash = row["crashing"] and bool(int(row["crashing"]))
        if tagged_crash and harness.name not in verified:
            if crash_path.exists():
                print(f"[!] {harness.name}: Input for tagged crash didn't reproduce!")
            else:
                print(f"[!] {harness.name}: Missing reproducer for tagged harness!")
        if crash_path.exists() and not tagged_crash:
            if harness.name in verified:
                print(f"[!] {harness.name}: Crash reproduced but not tagged!")
            else:
                print(f"[!] {crash_path} exists but doesn't reproduce!")

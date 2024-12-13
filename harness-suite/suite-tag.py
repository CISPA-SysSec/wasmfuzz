#!/usr/bin/env python3

import subprocess
from pathlib import Path
from pprint import pprint
import argparse
import csv
import io

parser = argparse.ArgumentParser()
parser.add_argument('--harness-dir', default="./out/")
parser.add_argument('--corpus-dir', default="./corpus/")

args = parser.parse_args()
assert Path(args.harness_dir).exists()
harness_dir = Path(args.harness_dir)
corpus_dir = Path(args.corpus_dir)

from collections import Counter, defaultdict

from enum import Enum
class Tag(Enum):
    FUZZBENCH = "fuzzbench"

    LANG_C = "lang-c"
    LANG_CPP = "lang-cpp"
    LANG_RUST = "lang-rust"

    CRASHING = "crashing"

    SLOW = "slow"
    SHALLOW = "shallow"
    BIG = "big"
    PROGRESS_24H = "progress-24h"

    # TODO: manually tag these
    BUGGY_HARNESS_UPSTREAM = "buggy-harness-upstream"
    BUGGY_PORT = "buggy-port"
    BUGGY_PROJECT = "buggy-project"
    TODO_REPORT = "todo-report"
    TODO_INVESTIGATE = "todo-investigate"


tags = defaultdict(set)


def tag_compilers():
    producers_ctr = Counter()
    for harness in harness_dir.glob("*.wasm"):

        producers = subprocess.check_output(["llvm-readelf", "--string-dump", "producers", harness]).decode()
        producers = [x.split("] ")[1] for x in producers.splitlines() if x.startswith("[")]
        producers_ctr.update(producers)

        harness = harness.name
        if ".Rust" in producers:
            tags[harness].add(Tag.LANG_RUST)

        if any(x.startswith(".C_plus_plus") for x in producers):
            tags[harness].add(Tag.LANG_CPP)

        if any(x.startswith("..language..C") for x in producers):
            # wasi-sdk code is always present, so: only activate this if none of
            # the other two languages were detected
            if Tag.LANG_CPP not in tags[harness] and Tag.LANG_RUST not in tags[harness]:
                tags[harness].add(Tag.LANG_C)

    print("`llvm-readelf --string-dump producers` summary:")
    pprint(producers_ctr)


def tag_fuzzbench(fuzzbench_harnesses):
    for harness in fuzzbench_harnesses:
        if not (harness_dir / harness).is_file():
            print("[WARN] missing harness from fuzzbench list:", harness)
            continue
        tags[harness].add(Tag.FUZZBENCH)


def tag_manually(harness, rev, *manual_tags):
    if not (harness_dir / harness).is_file():
        print("[WARN] missing harness for tag_manually:", harness)
        return

    # Verify that the revision matches
    try:
        git_metadata = subprocess.check_output(["llvm-objcopy", "--dump-section", "git-metadata.csv=-", harness])
    except Exception as e:
        print(e)
        return
    git_metadata = io.StringIO(git_metadata.decode())
    reader = csv.DictReader(git_metadata)
    revisions = [row["pinrev"] for row in reader]
    if rev not in revisions:
        print(f"[WARN] tag_manually {harness=} {rev=} unexpected revision, outdated?")

    tags[harness].update(manual_tags)



def tag_from_corpus():
    if not corpus_dir.is_dir():
        print("[WARN] missing harness corpi, can't tag crashes, complexity, progress")
        return

    def snapshot_path_to_minutes(path):
        r = path.stem.removeprefix("snapshot-").split("-")
        r = [int(x[:-1]) for x in r]
        return sum(a * b for a, b in zip(r, (
            60*24,
            60,
            1
        )))

    def snapshot_summary(path):
        crashes = False
        entry_edges = []
        execs_us = []
        total_edges = 0
        with open(path, "r") as f:
            for elem in csv.DictReader(f):
                if elem["crashed"] and int(elem["crashed"]):
                    crashes = True
                if elem["edge_cov"]:
                    entry_edges.append(int(elem["edge_cov"]))
                if elem["exec_us"] and elem["edge_cov"]:
                    execs_us.append(int(elem["exec_us"]))
                if elem["total_edge_cov"]:
                    total_edges = int(elem["total_edge_cov"])

        return dict(
            crashes=crashes,
            min_edges=min(entry_edges, default=None) or 0,
            max_edges=max(entry_edges, default=None) or 0,
            max_execs_us=max(execs_us, default=None) or 0,
            total_edges=total_edges,
            entries=len(entry_edges)
        )


    for harness in harness_dir.glob("*.wasm"):
        snapshots = sorted(list(corpus_dir.glob(f"{harness.stem}/snapshot-*.csv")), key=snapshot_path_to_minutes)
        if not snapshots:
            print("[WARN] corpus not found for harness", harness)
            continue

        harness = harness.name
        summaries = [snapshot_summary(x) for x in snapshots]
        pprint(summaries)

        # Check that crashing harnesses were tagged properly
        if summaries[-1]["crashes"]:
            if Tag.CRASHING not in tags[harness]:
                print(f"[WARN] harness {harness} crashed unexpectedly ({tags[harness] = })")
            tags[harness].add(Tag.CRASHING)
        else:
            if Tag.CRASHING in tags[harness]:
                print(f"[WARN] harness was tagged as crashing we don't have a crashing input")

        # Are there inputs that trigger sufficiently different amounts of coverage?
        if summaries[-1]["max_edges"] - summaries[-1]["min_edges"] < summaries[-1]["max_edges"] / 3 or summaries[-1]["entries"] < 500:
            tags[harness].add(Tag.SHALLOW)

        if summaries[-1]["total_edges"] > 2000:
            tags[harness].add(Tag.BIG)

        if summaries[-1]["max_execs_us"] > 0.1e6: # 0.1 seconds
            tags[harness].add(Tag.SLOW)

        # Did we make meaningful progress between the last two snapshots?
        if len(summaries) >= 2 and summaries[-1]["total_edges"] >= summaries[-2]["total_edges"] * 1.1:
            tags[harness].add(Tag.PROGRESS_24H)



tag_fuzzbench([
    # "bloaty-fuzz_target.wasm",
    # "curl-curl_fuzzer_http.wasm",
    "freetype2-ftfuzzer.wasm",
    # "harfbuzz-hb-shape-fuzzer.wasm",
    # "jsoncpp-fuzzer.wasm",
    # "lcms-cms_transform_fuzzer.wasm",
    "lcms-cms_transform.wasm",
    # "libjpeg-turbo-fuzzer.wasm",
    # "libpcap-fuzz-both.wasm",
    "libxml2-xml.wasm",
    # "libxslt-xpath.wasm",
    "mbedtls-fuzz_dtlsclient.wasm",
    "openssl-x509.wasm",
    # "openthread-ot-ip6-send-fuzzer.wasm",
    # "proj4-proj_crs_to_crs_fuzzer.wasm",
    # "re2-fuzzer.wasm",
    "sqlite-ossfuzz.wasm",
    # "systemd-fuzz-link-parser.wasm",
    # "vorbis-decode-fuzzer.wasm",
    # "woff2-convert-woff2ttf-fuzzer.wasm",
    "zlib-uncompress.wasm",
])

tag_manually("libbzip2-rs-decompress_chunked.wasm", "10b667e381e643547bd3bb45133526e4956c8b53",
             Tag.CRASHING, Tag.BUGGY_PROJECT, Tag.TODO_REPORT)
tag_manually("libbzip2-rs-compress.wasm", "10b667e381e643547bd3bb45133526e4956c8b53",
             Tag.CRASHING, Tag.BUGGY_HARNESS_UPSTREAM)

tag_from_corpus()

tag_compilers()

with open('tags.csv', 'w') as csvfile:
    fieldnames = ["harness"] + [t.value for t in Tag]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()
    for harness in harness_dir.glob("*.wasm"):
        harness = harness.name
        d = {t.value: int(t in tags[harness]) for t in Tag}
        d["harness"] = harness
        writer.writerow(d)

print("Wrote 'tags.csv'.")
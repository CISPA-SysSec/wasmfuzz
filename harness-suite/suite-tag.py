#!/usr/bin/env python3

import argparse
import csv
import io
import json
import subprocess
from collections import Counter, defaultdict
from enum import Enum
from pathlib import Path
from pprint import pprint
from typing import Dict, Union

parser = argparse.ArgumentParser()
parser.add_argument("--harness-dir", default="./out/")
parser.add_argument("--corpus-dir", default="./corpus/")

args = parser.parse_args()
assert Path(args.harness_dir).exists()
harness_dir = Path(args.harness_dir)
corpus_dir = Path(args.corpus_dir)
harness_paths = sorted(list(harness_dir.glob("*.wasm")))
harnesses = [x.name for x in harness_paths]


class Tag(Enum):
    SUITE = "suite"
    SUITE_BUGBENCH = "suite-bugbench"
    CRASHING = "crashing"

    LANG_C = "lang-c"
    LANG_CPP = "lang-cpp"
    LANG_RUST = "lang-rust"

    SLOW = "slow"
    FAST = "fast"
    SHALLOW = "shallow"
    BIG = "big"
    PROGRESS_24H = "progress-24h"

    # Note: These are tagged manually
    FUZZBENCH = "fuzzbench"
    BUGGY_HARNESS_UPSTREAM = "buggy-harness-upstream"
    WASM_SPECIFIC_CRASH = "wasm-specific-crash"
    BUGGY_PORT = "buggy-port"
    BUGGY_PROJECT = "buggy-project"
    SKIP = "skip"
    LOD = "lod"


tags = defaultdict(set)


def tag_compilers():
    producers_ctr = Counter()
    for harness_path in harness_paths:
        producers = subprocess.check_output(
            ["llvm-readelf", "--string-dump", "producers", harness_path]
        ).decode()
        producers = [
            x.split("] ")[1] for x in producers.splitlines() if x.startswith("[")
        ]
        producers_ctr.update(producers)

        harness = harness_path.name
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
        git_metadata = subprocess.check_output(
            [
                "llvm-objcopy",
                "--dump-section",
                "git-metadata.csv=-",
                harness_dir / harness,
            ]
        )
    except Exception as e:
        print(e)
        return
    git_metadata = io.StringIO(git_metadata.decode())
    reader = csv.DictReader(git_metadata)
    revisions = [row["pinrev"] for row in reader]
    if rev not in revisions and rev != "*":
        print(f"[WARN] tag_manually {harness=} {rev=} unexpected revision, outdated?")
        pprint(revisions)

    tags[harness].update(manual_tags)


total_edges = {}


def tag_from_corpus():
    if not corpus_dir.is_dir():
        print("[WARN] missing harness corpi, can't tag crashes, complexity, progress")
        return

    def snapshot_path_to_minutes(path):
        r = path.stem.removeprefix("snapshot-").split("-")
        r = [int(x[:-1]) for x in r]
        return sum(a * b for a, b in zip(r, (60 * 24, 60, 1)))

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
            entries=len(entry_edges),
        )

    for harness_path in harness_paths:
        snapshots = sorted(
            list(corpus_dir.glob(f"{harness_path.stem}/snapshot-*.csv")),
            key=snapshot_path_to_minutes,
        )
        if not snapshots:
            print("[WARN] corpus not found for harness", harness_path)
            continue

        harness = harness_path.name
        summaries = [snapshot_summary(x) for x in snapshots]
        total_edges[harness] = summaries[-1]["total_edges"]
        # pprint(summaries)

        # Check that crashing harnesses were tagged properly
        if summaries[-1]["crashes"]:
            if Tag.CRASHING not in tags[harness]:
                print(
                    f"[WARN] harness {harness} crashed unexpectedly ({tags[harness] = })"
                )
            tags[harness].add(Tag.CRASHING)
        else:
            if Tag.CRASHING in tags[harness]:
                print(
                    f"[INFO] harness {harness!r} was tagged as crashing but wasmfuzz corpus doesn't have a crashing input"
                )
        if summaries[0]["crashes"]:
            tags[harness].add(Tag.SHALLOW)

        # Are there inputs that trigger sufficiently different amounts of coverage?
        if (
            summaries[-1]["max_edges"] - summaries[-1]["min_edges"]
            < summaries[-1]["max_edges"] / 3
            or summaries[-1]["entries"] < 500
        ):
            tags[harness].add(Tag.SHALLOW)

        if summaries[-1]["total_edges"] > 4000:
            tags[harness].add(Tag.BIG)

        if summaries[-1]["max_execs_us"] > 100_000:  # 100ms
            tags[harness].add(Tag.SLOW)
        if summaries[-1]["max_execs_us"] < 200:  # 0.2ms -> at least 500 execs/s
            tags[harness].add(Tag.FAST)

        # Did we make meaningful progress in the last two snapshots?
        if (
            len(summaries) >= 3
            and snapshot_path_to_minutes(snapshots[-1]) >= 60 * 4
            and summaries[-1]["total_edges"] >= summaries[-3]["total_edges"] * 1.3
        ):
            tags[harness].add(Tag.PROGRESS_24H)


tag_fuzzbench(
    [
        # "bloaty-fuzz_target.wasm",
        # "curl-curl_fuzzer_http.wasm",
        "freetype2-ftfuzzer.wasm",
        # "harfbuzz-hb-shape-fuzzer.wasm",
        # "jsoncpp-fuzzer.wasm",
        "lcms-cms_transform.wasm",
        # "libjpeg-turbo-fuzzer.wasm",
        # "libpcap-fuzz-both.wasm",
        "libxml2-xml.wasm",
        # "libxslt-xpath.wasm",
        "mbedtls-fuzz_dtlsclient.wasm",
        "openssl-x509.wasm",
        # "openthread-ot-ip6-send-fuzzer.wasm",
        "openthread-radio-one-node.wasm",
        # "proj4-proj_crs_to_crs_fuzzer.wasm",
        # "re2-fuzzer.wasm",
        "sqlite-ossfuzz.wasm",
        # "systemd-fuzz-link-parser.wasm",
        "vorbis-decode.wasm",
        "woff2-convert_woff2ttf.wasm",
        "zlib-uncompress.wasm",
    ]
)


PROJS = {"libpng", "freetype2", "jsoncpp"}
for harness in harnesses:
    if any(harness.startswith(proj) for proj in PROJS):
        # The other WebAssembly fuzzers in our evaluation can't handle our
        # setjmp/longjmp harnesses since they are not snapshot-based and exiting
        # fuzz test cases would leak memory or corrupt state.
        tags[harness].add(Tag.SKIP)

for harness in harnesses:
    if harness.startswith("fuzzer-challenges"):
        tags[harness].add(Tag.CRASHING)
        tags[harness].add(Tag.SKIP)

# This is the only harness with `LLVMFuzzerCustomMutator`. Our fuzzers don't
# support custom mutators currently.
tag_manually("x509-parser-x509_with_mutator.wasm", "*", Tag.SKIP)

tag_from_corpus()

tag_compilers()

group_skip_small_dup = set()
group_sizes = defaultdict(set)
for harness in harnesses:
    key = harness.split(".")[0].split("-")[0]
    group_sizes[key].add(total_edges.get(harness, 0))

# pick the nth-largest size as the minimum for each group
MAX_SUITE_PER_PROJECT = 1
group_min_size = {
    key: sorted(sizes)[::-1][:MAX_SUITE_PER_PROJECT][-1]
    for key, sizes in group_sizes.items()
}
for harness in harnesses:
    key = harness.split(".")[0].split("-")[0]
    if total_edges.get(harness, 0) < group_min_size[key]:
        group_skip_small_dup.add(harness)

for harness in harnesses:
    t = tags[harness]

    # These harnesses aren't useful for evaluation since there doesn't seem to
    # be enough different code-paths to explore.
    if Tag.SHALLOW in t:
        continue
    # Skip explicitly ignored targets that shouldn't end up in the harness suite.
    if Tag.SKIP in t:
        continue

    if Tag.CRASHING in t:
        t.add(Tag.SUITE_BUGBENCH)
    elif (
        Tag.PROGRESS_24H in t
        or Tag.FUZZBENCH in t
        or Tag.BIG in t
    ) and harness not in group_skip_small_dup:
        t.add(Tag.SUITE)


interesting = [
    "cmark-gfm-fuzz-quadratic-brackets", "goblin-parse", "html5ever-fuzz_document_parse",
    "lcms-cms_transform_all", "libsndfile-alt", "libxml2-xml", "mbedtls-fuzz_dtlsclient",
    "openssl-server", "openssl-x509", "openthread-radio-one-node", "pcre2-fuzzcheck",
    "regex-ast_fuzz_match", "vorbis-decode", "woff2-convert_woff2ttf",
]
for harness in interesting:
    if Tag.SUITE not in tags[harness + ".wasm"]:
        print(f"[WARN] harness {harness} is not in the suite ({tags[harness + ".wasm"] = })")

lod = [
    # "expat-xml_parsebuffer_UTF-8",
    "firefox-fuzz_target_qcms",
    "fontations-fuzz_skrifa_outline", "freetype2-ftfuzzer", "goblin-parse",
    "graphite-font", #"image-script_png",
    "image-script_jpeg", "image-script_tiff",
    "image-script_ico", # "image-script_webp", # "image-script_guess",
    "jxl-oxide-libfuzzer-decode", "jxl-rs-decode", "lcms-cms_transform_all",
    "lewton-parse_ogg",
    # "libarchive-ossfuzz", "libarchive-upstream", # TODO: OOMs with non-snapshot fuzzing
    "libpng-read",
    "libsndfile", "libtiff-read_rgba", "libwebp-dwebp",
    "openjpeg-opj_decompress_J2K", # "openjpeg-opj_decompress_JP2",
    "openssl-acert", # "openssl-crl", "openssl-x509",  # openthread? # jbig2dec? # mbedtls?
    # "quick-xml-fuzz_target_1",
    # "sqlite-ossfuzz",
    #"stb-png_read",
    "symphonia-decode_any",
    "vorbis-decode", "woff2-convert_woff2ttf",
    "x509-parser-certreq",
    #"x509-parser-crl",
    # "x509-parser-x509_parse",
    "zune-image-zune-jpeg-decode_incremental",
    # Note: these seem saturated in both lod and no-lod?
    # "claxon-decode_full", "zip2-zip2-read"
]
for x in lod:
    if x + ".wasm" not in tags:
        print(f"[WARN] harness {x} is not in the suite ({tags[x + ".wasm"] = })")
        continue
    tags[x + ".wasm"].add(Tag.LOD)

print(f"Tag.SUITE: ({len([k for k, v in tags.items() if Tag.SUITE in v])})")
pprint(sorted({k for k, v in tags.items() if Tag.SUITE in v}))
print(f"Tag.SUITE_BUGBENCH: ({len([k for k, v in tags.items() if Tag.SUITE_BUGBENCH in v])})")
pprint(sorted({k for k, v in tags.items() if Tag.SUITE_BUGBENCH in v}))

with open("tags.csv", "w") as csvfile:
    fieldnames = ["harness"] + [t.value for t in Tag]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()
    for harness in harnesses:
        d: Dict[str, Union[int, str]] = {}
        d = {t.value: int(t in tags[harness]) for t in Tag}
        d["harness"] = harness
        writer.writerow(d)

print("Wrote 'tags.csv'.")

with open("tags.json", "w") as f:
    obj = {harness: sorted(t.value for t in tags[harness]) for harness in harnesses}
    json.dump(obj, f)

with open("tags.txt", "w") as f:
    for harness in harnesses:
        ts = sorted(t.value for t in tags[harness])
        f.write(f"{harness}: {', '.join(ts)}\n")

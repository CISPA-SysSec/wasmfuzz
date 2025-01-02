#!/usr/bin/env python3

import subprocess
import argparse
import csv
import io

from pathlib import Path
from pprint import pprint
from collections import Counter, defaultdict
from enum import Enum

parser = argparse.ArgumentParser()
parser.add_argument('--harness-dir', default="./out/")
parser.add_argument('--corpus-dir', default="./corpus/")

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
    REQUIRES_SJLJ = "requires-sjlj"
    BUGGY_HARNESS_UPSTREAM = "buggy-harness-upstream"
    WASM_SPECIFIC_CRASH = "wasm-specific-crash"
    BUGGY_PORT = "buggy-port"
    BUGGY_PROJECT = "buggy-project"


tags = defaultdict(set)

def tag_compilers():
    producers_ctr = Counter()
    for harness_path in harness_paths:
        producers = subprocess.check_output(["llvm-readelf", "--string-dump", "producers", harness_path]).decode()
        producers = [x.split("] ")[1] for x in producers.splitlines() if x.startswith("[")]
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
        git_metadata = subprocess.check_output(["llvm-objcopy", "--dump-section", "git-metadata.csv=-", harness_dir / harness])
    except Exception as e:
        print(e)
        return
    git_metadata = io.StringIO(git_metadata.decode())
    reader = csv.DictReader(git_metadata)
    revisions = [row["pinrev"] for row in reader]
    if rev not in revisions:
        print(f"[WARN] tag_manually {harness=} {rev=} unexpected revision, outdated?")

    tags[harness].update(manual_tags)



total_edges = {}
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


    for harness_path in harness_paths:
        snapshots = sorted(list(corpus_dir.glob(f"{harness_path.stem}/snapshot-*.csv")), key=snapshot_path_to_minutes)
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
                print(f"[WARN] harness {harness} crashed unexpectedly ({tags[harness] = })")
            tags[harness].add(Tag.CRASHING)
        else:
            if Tag.CRASHING in tags[harness]:
                print(f"[WARN] harness {harness!r} was tagged as crashing but we don't have a crashing input")

        # Are there inputs that trigger sufficiently different amounts of coverage?
        if summaries[-1]["max_edges"] - summaries[-1]["min_edges"] < summaries[-1]["max_edges"] / 3 or summaries[-1]["entries"] < 500:
            tags[harness].add(Tag.SHALLOW)

        if summaries[-1]["total_edges"] > 4000:
            tags[harness].add(Tag.BIG)

        if summaries[-1]["max_execs_us"] > 100_000: # 100ms
            tags[harness].add(Tag.SLOW)
        if summaries[-1]["max_execs_us"] < 200: # 0.2ms -> at least 500 execs/s
            tags[harness].add(Tag.FAST)

        # Did we make meaningful progress in the last two snapshots?
        if len(summaries) >= 3 and snapshot_path_to_minutes(snapshots[-1]) >= 60*4 and summaries[-1]["total_edges"] >= summaries[-3]["total_edges"] * 1.3:
            tags[harness].add(Tag.PROGRESS_24H)



tag_fuzzbench([
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
    # "proj4-proj_crs_to_crs_fuzzer.wasm",
    # "re2-fuzzer.wasm",
    "sqlite-ossfuzz.wasm",
    # "systemd-fuzz-link-parser.wasm",
    # "vorbis-decode-fuzzer.wasm",
    # "woff2-convert-woff2ttf-fuzzer.wasm",
    "zlib-uncompress.wasm",
])


# TODO: report
tag_manually("libbzip2-rs-decompress_chunked.wasm", "700054948bbac76e029028fe6932c767f8fa6a1a",
             Tag.CRASHING, Tag.BUGGY_PROJECT)
tag_manually("libbzip2-rs-compress.wasm", "700054948bbac76e029028fe6932c767f8fa6a1a",
             Tag.CRASHING, Tag.BUGGY_HARNESS_UPSTREAM)
# TODO
tag_manually("libbzip2-rs-decompress.wasm", "700054948bbac76e029028fe6932c767f8fa6a1a",
             Tag.CRASHING)

# [STDOUT] thread '<unnamed>' panicked at fuzz_targets/bench/lib.rs:95:22:
# [STDOUT] [...]
# TODO: investigate
tag_manually("ron-arbitrary.wasm", "74666478d5553592c6136e0dec12d11bbd10302e", Tag.CRASHING, Tag.WASM_SPECIFIC_CRASH)

# [STDOUT] thread '<unnamed>' panicked at /projects/naga/repo/src/front/glsl/lex.rs:35:42:
# [STDOUT] called `Result::unwrap()` on an `Err` value: (UnexpectedCharacter, Location { start: 0, end: 0, line: 1 })
# [STDOUT] note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
# execution trapped with Abort(UnreachableReached) which indicates that the target crashed
tag_manually("naga-glsl_parser.wasm", "d0f28c0b1a3c772e55e68db1c47eff5131cb6732", Tag.CRASHING, Tag.BUGGY_PROJECT)
tag_manually("naga-wgsl_parser.wasm", "d0f28c0b1a3c772e55e68db1c47eff5131cb6732", Tag.CRASHING, Tag.BUGGY_PROJECT)
tag_manually("naga-spv_parser.wasm", "d0f28c0b1a3c772e55e68db1c47eff5131cb6732", Tag.CRASHING, Tag.BUGGY_PROJECT)

# [STDOUT] thread '<unnamed>' panicked at /projects/naga/repo/src/valid/analyzer.rs:1004:82:
# [STDOUT] index out of bounds: the len is 1 but the index is 3132799673
# [STDOUT] note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
# execution trapped with Abort(UnreachableReached) which indicates that the target crashed
tag_manually("naga-ir.wasm", "d0f28c0b1a3c772e55e68db1c47eff5131cb6732", Tag.CRASHING, Tag.BUGGY_PROJECT)


# rust-analyzer's syntax crate crashes instantly with the native fuzzing setup...
tag_manually("rust-analyzer-reparse.wasm", "8dd53a3a46adffdc7928bbfabab90d6348c9a089", Tag.CRASHING, Tag.BUGGY_PROJECT)
tag_manually("rust-analyzer-parser.wasm", "8dd53a3a46adffdc7928bbfabab90d6348c9a089", Tag.CRASHING, Tag.BUGGY_PROJECT)

# Testcase: "corpus/symphonia-decode_any/snapshot-0d-4h-0m/b702b178e273440a992dacbd6ec6e6b7"
# [STDOUT] thread '<unnamed>' panicked at rustlib/src/rust/library/core/src/iter/adapters/step_by.rs:35:9:
# [STDOUT] assertion failed: step != 0
# reproduces upstream almost instantly
tag_manually("symphonia-decode_any.wasm", "64171c336be5519692c8149968ae2fe1fb7ef8e5", Tag.CRASHING, Tag.BUGGY_PROJECT)

# Unresolved virtual call in ossl_rand_drbg_new -> abort in `undefined_stub`
tag_manually("openssl-provider.wasm", "3d3bb26a13dcc67f99e66de6a44ae9ced117f64b",
             Tag.CRASHING, Tag.BUGGY_PORT)
# Their harness builds on global mutable state to reach coverage. We patch the
# harness to do multiple iterations but something's not quite right apparently.
tag_manually("openssl-hashtable.wasm", "3d3bb26a13dcc67f99e66de6a44ae9ced117f64b",
             Tag.CRASHING, Tag.BUGGY_PORT)

# Goblin's PE parser is a bit crash-prone.
tag_manually("goblin-parse.wasm", "48da3d867b47173b19072b30bd3ef21e7d0215ba", Tag.CRASHING, Tag.BUGGY_PROJECT)

# JIT-TRACE: entering _204_ruff_python_parser::parser::expression::<impl ruff_python_parser::parser::Parser>::parse_atom::hab656e63ebc4e656 (Tracing(<none>, [stdout]))
# JIT-TRACE: entering _200_ruff_python_parser::parser::Parser::bump::h0a7d407e407cc458 (Tracing(<none>, [stdout]))
# execution trapped with Cranelift(HeapOutOfBounds) which indicates that the target crashed
# TODO: investigate
tag_manually("ruff-ruff_parse_simple.wasm", "5c537b6dbbb8c3cd9ff13869fb2817f81b615da9", Tag.CRASHING, Tag.BUGGY_PORT)
tag_manually("ruff-ruff_parse_idempotency.wasm", "5c537b6dbbb8c3cd9ff13869fb2817f81b615da9", Tag.CRASHING, Tag.BUGGY_PORT)
tag_manually("ruff-ruff_formatter_idempotency.wasm", "5c537b6dbbb8c3cd9ff13869fb2817f81b615da9", Tag.CRASHING, Tag.BUGGY_PORT)
tag_manually("ruff-ruff_fix_validity.wasm", "5c537b6dbbb8c3cd9ff13869fb2817f81b615da9", Tag.CRASHING, Tag.BUGGY_PORT)

# TODO: investigate
tag_manually("image_script_jpeg.wasm", "2125965fdc23ea0544fd585f6e934cc7762c1f51", Tag.CRASHING, Tag.SUITE_BUGBENCH)
tag_manually("image_script_webp.wasm", "2125965fdc23ea0544fd585f6e934cc7762c1f51", Tag.CRASHING, Tag.SUITE_BUGBENCH)
# takes ~10 CPU hours with `wasmfuzz fuzz`
# TODO: reproduce on 64-bit?
# allocation limit of 512 MB reached with 257 byte input
tag_manually("image_script_hdr.wasm", "2125965fdc23ea0544fd585f6e934cc7762c1f51", Tag.CRASHING, Tag.SUITE_BUGBENCH)

# wasmfuzz doesn't find after 48+ CPU hours
# aflpp finds this reliably
# TODO: triage
tag_manually("ruff-ruff_formatter_validity.wasm", "5c537b6dbbb8c3cd9ff13869fb2817f81b615da9", Tag.CRASHING, Tag.SUITE_BUGBENCH)

# wasmfuzz doesn't find after 48+ CPU hours
# [STDOUT] thread '<unnamed>' panicked at /root/.rustup/toolchains/nightly-2024-12-11-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/core/src/num/f32.rs:1402:9:
# [STDOUT] min > max, or either was NaN. min = inf, max = -inf
# https://github.com/tirr-c/jxl-oxide/blob/45f76988a9ae70e66753fd1114a2ee6cfe963efd/crates/jxl-render/src/features/upsampling.rs#L107-L119
tag_manually("jxl-oxide-libfuzzer-decode.wasm", "f5343b2017cf19062840e06b837e4741b912181f", Tag.CRASHING, Tag.SUITE_BUGBENCH)

# corpus/zip2-fuzz_write/snapshot-0d-4h-0m/fcc11081e972f970ef563a73b57183ee
# execution trapped with Cranelift(HeapOutOfBounds) in fuzz_write::do_operation after deduplicate_paths
# TODO: investigate
tag_manually("zip2-fuzz_write.wasm", "6d3945645b7f3805068dd8c50d4fe56a66651069", Tag.CRASHING)

tag_manually("sequoia-decrypt_from_bytes.wasm", "daf94cf31eb7b9fbc4f89753f0b2eeddda650b4e", Tag.CRASHING)
tag_manually("sequoia-inline_verify_from_bytes.wasm", "daf94cf31eb7b9fbc4f89753f0b2eeddda650b4e", Tag.CRASHING)

PROJS = {"libpng", "freetype2", "jsoncpp"}
for harness in harnesses:
    if any(harness.startswith(proj) for proj in PROJS):
        tags[harness].add(Tag.REQUIRES_SJLJ)

tag_from_corpus()

tag_compilers()

group_largest = set()
group_max_total = defaultdict(lambda: 0)
for harness in harnesses:
    key = harness.split(".")[0].split("-")[0]
    group_max_total[key] = max(group_max_total[key], total_edges.get(harness, 0))
for harness in harnesses:
    key = harness.split(".")[0].split("-")[0]
    if total_edges.get(harness, 0) >= group_max_total[key]:
        group_largest.add(harness)

for harness in harnesses:
    t = tags[harness]

    # These harnesses aren't useful for evaluation since there doesn't seem to
    # be enough different code-paths to explore.
    if Tag.SHALLOW in t: continue
    # The other WebAssembly fuzzers in our evaluation can't handle our
    # SetJump/LongJump harnesses since they are not snapshot-based and exiting
    # fuzz test cases would leak memory or corrupt state.
    if Tag.REQUIRES_SJLJ in t: continue

    if Tag.CRASHING in t:
        t.add(Tag.SUITE_BUGBENCH)
    elif Tag.PROGRESS_24H in t or Tag.FUZZBENCH in t or (Tag.BIG in t and harness in group_largest):
        t.add(Tag.SUITE)


print("Tag.SUITE:")
pprint(sorted({k for k, v in tags.items() if Tag.SUITE in v}))
print("Tag.SUITE_BUGBENCH:")
pprint(sorted({k for k, v in tags.items() if Tag.SUITE_BUGBENCH in v}))

with open('tags.csv', 'w') as csvfile:
    fieldnames = ["harness"] + [t.value for t in Tag]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()
    for harness in harnesses:
        d = {t.value: int(t in tags[harness]) for t in Tag}
        d["harness"] = harness
        writer.writerow(d)

print("Wrote 'tags.csv'.")

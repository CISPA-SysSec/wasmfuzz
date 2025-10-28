#!/usr/bin/env python3

import subprocess
import argparse
import csv
import json
import io

from pathlib import Path
from pprint import pprint
from collections import Counter, defaultdict
from enum import Enum
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
                    f"[WARN] harness {harness!r} was tagged as crashing but wasmfuzz doesn't have a crashing input"
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

# [naga/src/proc/layouter.rs:171:13] &ty.inner = Scalar {
#     kind: Float,
#     width: 63,
# }
# thread '<unnamed>' panicked at /code/_others/wgpu/naga/src/front/spv/mod.rs:5339:47:
# called `Result::unwrap()` on an `Err` value: LayoutError { ty: [0], inner: NonPowerOfTwoWidth }
tag_manually(
    "wgpu-spv_parser.wasm",
    "d55bb2956a2391e3cd003b837bb406b4c1440bc7",
    Tag.CRASHING,
    Tag.BUGGY_PROJECT,
)
tag_manually(
    "wgpu-glsl_parser.wasm",
    "d55bb2956a2391e3cd003b837bb406b4c1440bc7",
    Tag.CRASHING,
    Tag.BUGGY_PROJECT,
)

# [STDOUT] thread '<unnamed>' panicked at /projects/naga/repo/src/valid/analyzer.rs:1004:82:
# [STDOUT] index out of bounds: the len is 1 but the index is 3132799673
tag_manually(
    "wgpu-ir.wasm",
    "d55bb2956a2391e3cd003b837bb406b4c1440bc7",
    Tag.CRASHING,
    Tag.BUGGY_PROJECT,
)

# Note: naga's wgsl frontend is exposed in Firefox's WebGPU API, so keep it in the benchmark suite
# tag_manually("wgpu-wgsl_parser.wasm", "d55bb2956a2391e3cd003b837bb406b4c1440bc7", Tag.SUITE)
# https://github.com/gfx-rs/wgpu/issues/5757#issuecomment-2830427879
tag_manually(
    "wgpu-wgsl_parser.wasm", "d55bb2956a2391e3cd003b837bb406b4c1440bc7", Tag.CRASHING
)

# rust-analyzer's syntax crate crashes instantly with the native fuzzing setup...
tag_manually(
    "rust-analyzer-syntax-reparse.wasm",
    "bd06def3d3acd5f54fac953a015c0ac9b1e71b2f",
    Tag.CRASHING,
    Tag.BUGGY_PROJECT,
)
tag_manually(
    "rust-analyzer-syntax-parser.wasm",
    "bd06def3d3acd5f54fac953a015c0ac9b1e71b2f",
    Tag.CRASHING,
    Tag.BUGGY_PROJECT,
)

# Testcase: "corpus/symphonia-decode_any/snapshot-0d-4h-0m/b702b178e273440a992dacbd6ec6e6b7"
# [STDOUT] thread '<unnamed>' panicked at rustlib/src/rust/library/core/src/iter/adapters/step_by.rs:35:9:
# [STDOUT] assertion failed: step != 0
# reproduces upstream almost instantly
tag_manually(
    "symphonia-decode_any.wasm",
    "505458eb1e479d84df0a65f95ab3d536d6350d29",
    Tag.CRASHING,
    Tag.BUGGY_PROJECT,
)

# Their harness builds on global mutable state to reach coverage. We patch the
# harness to do multiple iterations but something's not quite right apparently.
tag_manually(
    "openssl-hashtable.wasm",
    "5857bdbb766a206f4efe7e8c72cf6721a625bd90",
    Tag.CRASHING,
    Tag.BUGGY_PORT,
)

# JIT-TRACE: entering _204_ruff_python_parser::parser::expression::<impl ruff_python_parser::parser::Parser>::parse_atom::hab656e63ebc4e656 (Tracing(<none>, [stdout]))
# JIT-TRACE: entering _200_ruff_python_parser::parser::Parser::bump::h0a7d407e407cc458 (Tracing(<none>, [stdout]))
# execution trapped with Cranelift(HeapOutOfBounds) which indicates that the target crashed
# TODO: investigate, are we running into stack overflows?
tag_manually(
    "ruff-ruff_parse_simple.wasm",
    "01695513ce33f1f1615309323ba145c42f4720c1",
    Tag.CRASHING,
    Tag.BUGGY_PORT,
)
tag_manually(
    "ruff-ruff_parse_idempotency.wasm",
    "01695513ce33f1f1615309323ba145c42f4720c1",
    Tag.CRASHING,
    Tag.BUGGY_PORT,
)
tag_manually(
    "ruff-ruff_formatter_idempotency.wasm",
    "01695513ce33f1f1615309323ba145c42f4720c1",
    Tag.CRASHING,
    Tag.BUGGY_PORT,
)
tag_manually(
    "ruff-ruff_fix_validity.wasm",
    "01695513ce33f1f1615309323ba145c42f4720c1",
    Tag.CRASHING,
    Tag.BUGGY_PORT,
)

# mcu_prog panic was fixed upstream in zune-image
tag_manually(
    "image-script_jpeg.wasm", "ceb71e59496a32dbe2a56599ff60d09cb0b8cb20", Tag.CRASHING
)
# https://github.com/image-rs/image-tiff/pull/305
tag_manually(
    "image-script_tiff.wasm",
    "ceb71e59496a32dbe2a56599ff60d09cb0b8cb20",
    Tag.CRASHING,
    Tag.BUGGY_PROJECT,
)

# Note: wasmfuzz doesn't find after 48+ CPU hours
#       aflpp finds this reliably
# TODO: triage
tag_manually(
    "ruff-ruff_formatter_validity.wasm",
    "01695513ce33f1f1615309323ba145c42f4720c1",
    Tag.CRASHING,
)


# The native port of rustc-demangle is missing updates
tag_manually(
    "rustc-demangle-native_c.wasm",
    "c5688cfec32d2bd00701836f12beb3560ee015b8",
    Tag.CRASHING,
    Tag.BUGGY_PROJECT,
)

# Bug benchmark: Re-introduce NaN issue https://github.com/tirr-c/jxl-oxide/pull/485
tag_manually(
    "jxl-oxide-libfuzzer-decode.wasm",
    "e653b3cd48529509fbd6bd85bdb5379e5848b779",
    Tag.CRASHING,
)

# [STDOUT] thread '<unnamed>' panicked at /projects/sequoia/repo/buffered-reader/src/lib.rs:826:9:
# [STDOUT] assertion failed: data.len() >= amount
tag_manually(
    "sequoia-cert_from_bytes.wasm",
    "05e6707ad2c68fa52a30c3c9a21d54dc00089919",
    Tag.CRASHING,
)
tag_manually(
    "sequoia-decrypt_from_bytes.wasm",
    "05e6707ad2c68fa52a30c3c9a21d54dc00089919",
    Tag.CRASHING,
)
tag_manually(
    "sequoia-inline_verify_from_bytes.wasm",
    "05e6707ad2c68fa52a30c3c9a21d54dc00089919",
    Tag.CRASHING,
)

# [STDOUT] thread '<unnamed>' panicked at /projects/zune-image/repo/crates/zune-core/src/bytestream/reader/no_std_readers.rs:104:58:
# [STDOUT] called `Option::unwrap()` on a `None` value
tag_manually(
    "zune-image-zune-bmp-decode_buffer.wasm",
    "ca5b0ef0cd3fe9535f875c904c8428e9f3706f41",
    Tag.CRASHING,
    Tag.BUGGY_PROJECT,
)
tag_manually(
    "zune-image-zune-png-decode_buffer.wasm",
    "ca5b0ef0cd3fe9535f875c904c8428e9f3706f41",
    Tag.CRASHING,
    Tag.BUGGY_PROJECT,
)
tag_manually(
    "zune-image-zune-png-roundtrip.wasm",
    "ca5b0ef0cd3fe9535f875c904c8428e9f3706f41",
    Tag.CRASHING,
    Tag.BUGGY_PROJECT,
)

# [STDOUT] thread '<unnamed>' panicked at /projects/lewton/repo/src/header.rs:505:29:
# [STDOUT] capacity overflow
tag_manually(
    "lewton-parse_ogg.wasm", "bb2955b717094b40260902cf2f8dd9c5ea62a84a", Tag.CRASHING
)
# NULL-deref in ARMT_Convert
tag_manually("lzma-7z.wasm", "d25e63d8f6b8186d04146cb19405bc5ad565412e", Tag.CRASHING)
# dense::DFA::from_bytes validation order bug
tag_manually(
    "regex-fuzz_regex_automata_deserialize_dense_dfa.wasm",
    "a76e0a0ef050f987d686268f1783a95b6bb25ea9",
    Tag.CRASHING,
)

# [STDOUT] thread '<unnamed>' panicked at fuzzers/canonicalize.rs:15:9:
# [STDOUT] assertion `left == right` failed
# [STDOUT]   left: [1, 0, 0, 128, 0, 0, 0, 0]
# [STDOUT]  right: [1, 0, 0, 0, 0, 0, 0, 0]
tag_manually(
    "capnproto-rust-canonicalize.wasm",
    "635a4e420b75bf247e75312e4e872aa0e7fb9558",
    Tag.CRASHING,
)
# [STDOUT] thread '<unnamed>' panicked at /projects/comrak/repo/src/parser/mod.rs:3348:21:
# [STDOUT] assertion failed: (sp.end.column - sp.start.column + 1 == x) || rem == 0
# => >https://github.com/kivikakk/comrak/issues/595
for target in ["fuzz_options", "gfm_footnotes", "commonmark"]:
    tag_manually(
        f"comrak-{target}.wasm",
        "36b06b8a9466e6109c9e162e18cabcd3ef8aead2",
        Tag.CRASHING,
    )
# tag_manually("comrak-quadratic.wasm", "36b06b8a9466e6109c9e162e18cabcd3ef8aead2", Tag.CRASHING)
# [STDOUT] thread '<unnamed>' panicked at /projects/toml-edit/repo/crates/toml_edit/src/parser/inline_table.rs:160:18:
# [STDOUT] setting a value should set a prefix
tag_manually(
    "toml-toml_edit_fuzz-parse_document.wasm",
    "80217f85ee8e6d91b4ed2469aecfdf93cef15985",
    Tag.CRASHING,
)
# [STDOUT] thread '<unnamed>' panicked at fuzz_targets/compress.rs:27:5:
# [STDOUT] assertion `left == right` failed
# [STDOUT]   left: Ok
# [STDOUT]  right: DataError
tag_manually(
    "zlib-rs-compress.wasm", "39838838ec2d49021548f90cec60cc3d8f56b188", Tag.CRASHING
)
# [STDOUT] thread '<unnamed>' panicked at fuzz_targets/inflate_chunked.rs:51:5:
# [STDOUT] assertion `left == right` failed
# [STDOUT]   left: StreamEnd
# [STDOUT]  right: Ok
tag_manually(
    "zlib-rs-inflate_chunked.wasm",
    "39838838ec2d49021548f90cec60cc3d8f56b188",
    Tag.CRASHING,
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
        or (Tag.BIG in t and harness in group_largest)
    ):
        t.add(Tag.SUITE)


print("Tag.SUITE:")
pprint(sorted({k for k, v in tags.items() if Tag.SUITE in v}))
print("Tag.SUITE_BUGBENCH:")
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

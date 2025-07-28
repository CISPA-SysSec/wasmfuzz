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
    BUGGY_HARNESS_UPSTREAM = "buggy-harness-upstream"
    WASM_SPECIFIC_CRASH = "wasm-specific-crash"
    BUGGY_PORT = "buggy-port"
    BUGGY_PROJECT = "buggy-project"
    SKIP = "skip"


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
                print(f"[WARN] harness {harness!r} was tagged as crashing but wasmfuzz doesn't have a crashing input")
        if summaries[0]["crashes"]:
            tags[harness].add(Tag.SHALLOW)

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
    "openthread-radio-one-node.wasm",
    # "proj4-proj_crs_to_crs_fuzzer.wasm",
    # "re2-fuzzer.wasm",
    "sqlite-ossfuzz.wasm",
    # "systemd-fuzz-link-parser.wasm",
    "vorbis-decode.wasm",
    "woff2-convert_woff2ttf.wasm",
    "zlib-uncompress.wasm",
])

# Note: These panics with "no filesystem on wasm" but only when trying to save the crash
# TODO: investigate
tag_manually("libbzip2-rs-decompress_chunked.wasm", "ed9e9c302a498024b7e96e920c704278b1da7866",
             Tag.CRASHING, Tag.BUGGY_PROJECT)
tag_manually("libbzip2-rs-decompress_random_input.wasm", "ed9e9c302a498024b7e96e920c704278b1da7866",
             Tag.CRASHING, Tag.BUGGY_PROJECT)


# [STDOUT] thread '<unnamed>' panicked at fuzz_targets/bench/lib.rs:95:22:
# [STDOUT] [...]
# TODO: investigate
tag_manually("ron-arbitrary.wasm", "27a26d691a24ac1eef3462086eed31dcbc0196f9", Tag.CRASHING, Tag.WASM_SPECIFIC_CRASH)

# [naga/src/proc/layouter.rs:171:13] &ty.inner = Scalar {
#     kind: Float,
#     width: 63,
# }
# thread '<unnamed>' panicked at /code/_others/wgpu/naga/src/front/spv/mod.rs:5339:47:
# called `Result::unwrap()` on an `Err` value: LayoutError { ty: [0], inner: NonPowerOfTwoWidth }
tag_manually("wgpu-spv_parser.wasm", "d55bb2956a2391e3cd003b837bb406b4c1440bc7", Tag.CRASHING, Tag.BUGGY_PROJECT)
tag_manually("wgpu-glsl_parser.wasm", "d55bb2956a2391e3cd003b837bb406b4c1440bc7", Tag.CRASHING, Tag.BUGGY_PROJECT)

# [STDOUT] thread '<unnamed>' panicked at /projects/naga/repo/src/valid/analyzer.rs:1004:82:
# [STDOUT] index out of bounds: the len is 1 but the index is 3132799673
tag_manually("wgpu-ir.wasm", "d55bb2956a2391e3cd003b837bb406b4c1440bc7", Tag.CRASHING, Tag.BUGGY_PROJECT)

# Note: naga's wgsl frontend is exposed in Firefox's WebGPU API, so keep it in the benchmark suite
# tag_manually("wgpu-wgsl_parser.wasm", "d55bb2956a2391e3cd003b837bb406b4c1440bc7", Tag.SUITE)
# https://github.com/gfx-rs/wgpu/issues/5757#issuecomment-2830427879
tag_manually("wgpu-wgsl_parser.wasm", "d55bb2956a2391e3cd003b837bb406b4c1440bc7", Tag.CRASHING)

# rust-analyzer's syntax crate crashes instantly with the native fuzzing setup...
tag_manually("rust-analyzer-syntax-reparse.wasm", "fe5a925a74efde7ec6a7d3e388b946f96d36e760", Tag.CRASHING, Tag.BUGGY_PROJECT)
tag_manually("rust-analyzer-syntax-parser.wasm", "fe5a925a74efde7ec6a7d3e388b946f96d36e760", Tag.CRASHING, Tag.BUGGY_PROJECT)

# Testcase: "corpus/symphonia-decode_any/snapshot-0d-4h-0m/b702b178e273440a992dacbd6ec6e6b7"
# [STDOUT] thread '<unnamed>' panicked at rustlib/src/rust/library/core/src/iter/adapters/step_by.rs:35:9:
# [STDOUT] assertion failed: step != 0
# reproduces upstream almost instantly
tag_manually("symphonia-decode_any.wasm", "ef9bbd8dd147b05cc911dafe0ae3663ae81b692d", Tag.CRASHING, Tag.BUGGY_PROJECT)

# Their harness builds on global mutable state to reach coverage. We patch the
# harness to do multiple iterations but something's not quite right apparently.
tag_manually("openssl-hashtable.wasm", "5857bdbb766a206f4efe7e8c72cf6721a625bd90",
             Tag.CRASHING, Tag.BUGGY_PORT)
# Unresolved virtual call in ossl_rand_drbg_new -> abort in `undefined_stub`
tag_manually("openssl-provider.wasm", "5857bdbb766a206f4efe7e8c72cf6721a625bd90", Tag.CRASHING, Tag.BUGGY_PORT)
tag_manually("openssl-ml-dsa.wasm", "5857bdbb766a206f4efe7e8c72cf6721a625bd90", Tag.CRASHING, Tag.BUGGY_PORT)
tag_manually("openssl-ml-kem.wasm", "5857bdbb766a206f4efe7e8c72cf6721a625bd90", Tag.CRASHING, Tag.BUGGY_PORT)
tag_manually("openssl-slh-dsa.wasm", "5857bdbb766a206f4efe7e8c72cf6721a625bd90", Tag.CRASHING, Tag.BUGGY_PORT)

# JIT-TRACE: entering _204_ruff_python_parser::parser::expression::<impl ruff_python_parser::parser::Parser>::parse_atom::hab656e63ebc4e656 (Tracing(<none>, [stdout]))
# JIT-TRACE: entering _200_ruff_python_parser::parser::Parser::bump::h0a7d407e407cc458 (Tracing(<none>, [stdout]))
# execution trapped with Cranelift(HeapOutOfBounds) which indicates that the target crashed
# TODO: investigate, are we running into stack overflows?
tag_manually("ruff-ruff_parse_simple.wasm", "5c537b6dbbb8c3cd9ff13869fb2817f81b615da9", Tag.CRASHING, Tag.BUGGY_PORT)
tag_manually("ruff-ruff_parse_idempotency.wasm", "5c537b6dbbb8c3cd9ff13869fb2817f81b615da9", Tag.CRASHING, Tag.BUGGY_PORT)
tag_manually("ruff-ruff_formatter_idempotency.wasm", "5c537b6dbbb8c3cd9ff13869fb2817f81b615da9", Tag.CRASHING, Tag.BUGGY_PORT)
tag_manually("ruff-ruff_fix_validity.wasm", "5c537b6dbbb8c3cd9ff13869fb2817f81b615da9", Tag.CRASHING, Tag.BUGGY_PORT)

# [STDOUT] memory allocation of 714407892 bytes failed
tag_manually("image_script_webp.wasm", "8371fae97239be01131bc47ebd79896d0a65537a", Tag.CRASHING, Tag.SUITE_BUGBENCH)
# takes ~10 CPU hours with `wasmfuzz fuzz`
# TODO: reproduce on 64-bit?
# allocation limit of 512 MB reached with 257 byte input
tag_manually("image_script_hdr.wasm", "8371fae97239be01131bc47ebd79896d0a65537a", Tag.CRASHING, Tag.SUITE_BUGBENCH)
tag_manually("image_script_tga.wasm", "8371fae97239be01131bc47ebd79896d0a65537a", Tag.CRASHING, Tag.SUITE_BUGBENCH)
# thread '<unnamed>' panicked at /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/png-0.17.16/src/decoder/transform/palette.rs:74:61:
# range end index 3 out of range for slice of length 1
tag_manually("image_script_png.wasm", "8371fae97239be01131bc47ebd79896d0a65537a", Tag.CRASHING)
tag_manually("image_script_guess.wasm", "8371fae97239be01131bc47ebd79896d0a65537a", Tag.CRASHING)

# Note: wasmfuzz doesn't find after 48+ CPU hours
#       aflpp finds this reliably
# TODO: triage
tag_manually("ruff-ruff_formatter_validity.wasm", "5c537b6dbbb8c3cd9ff13869fb2817f81b615da9", Tag.CRASHING, Tag.SUITE_BUGBENCH)

# wasmfuzz doesn't find after 48+ CPU hours
# [STDOUT] thread '<unnamed>' panicked at /root/.rustup/toolchains/nightly-2024-12-11-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/core/src/num/f32.rs:1402:9:
# [STDOUT] min > max, or either was NaN. min = inf, max = -inf
# https://github.com/tirr-c/jxl-oxide/blob/45f76988a9ae70e66753fd1114a2ee6cfe963efd/crates/jxl-render/src/features/upsampling.rs#L107-L119
tag_manually("jxl-oxide-libfuzzer-decode.wasm", "7de618ff1331cd6807b4f9e9bd52b5be0fe0b8f0", Tag.CRASHING, Tag.SUITE_BUGBENCH)

# corpus/zip2-fuzz_write/snapshot-0d-4h-0m/fcc11081e972f970ef563a73b57183ee
# execution trapped with Cranelift(HeapOutOfBounds) in fuzz_write::do_operation after deduplicate_paths
# TODO: investigate
tag_manually("zip2-fuzz_write.wasm", "6d3945645b7f3805068dd8c50d4fe56a66651069", Tag.CRASHING)

# [STDOUT] thread '<unnamed>' panicked at /projects/sequoia/repo/buffered-reader/src/lib.rs:826:9:
# [STDOUT] assertion failed: data.len() >= amount
tag_manually("sequoia-cert_from_bytes.wasm", "c948071849fe2b3baf590435eaaaf09fbef138be", Tag.CRASHING)
tag_manually("sequoia-decrypt_from_bytes.wasm", "c948071849fe2b3baf590435eaaaf09fbef138be", Tag.CRASHING)
tag_manually("sequoia-inline_verify_from_bytes.wasm", "c948071849fe2b3baf590435eaaaf09fbef138be", Tag.CRASHING)

# [STDOUT] thread '<unnamed>' panicked at /projects/zune-image/repo/crates/zune-core/src/bytestream/reader/no_std_readers.rs:104:58:
# [STDOUT] called `Option::unwrap()` on a `None` value
tag_manually("zune-image-zune-bmp-decode_buffer.wasm", "f873e3f01e2cfa3f23bc698290f2d68dda5f846d", Tag.CRASHING, Tag.BUGGY_PROJECT)
tag_manually("zune-image-zune-png-decode_buffer.wasm", "f873e3f01e2cfa3f23bc698290f2d68dda5f846d", Tag.CRASHING, Tag.BUGGY_PROJECT)
tag_manually("zune-image-zune-ppm-decode_buffer.wasm", "f873e3f01e2cfa3f23bc698290f2d68dda5f846d", Tag.CRASHING, Tag.BUGGY_PROJECT)
tag_manually("zune-image-zune-psd-decode_buffer.wasm", "f873e3f01e2cfa3f23bc698290f2d68dda5f846d", Tag.CRASHING, Tag.BUGGY_PROJECT)
tag_manually("zune-image-zune-qoi-decode_buffer.wasm", "f873e3f01e2cfa3f23bc698290f2d68dda5f846d", Tag.CRASHING, Tag.BUGGY_PROJECT)
tag_manually("zune-image-zune-png-roundtrip.wasm",     "f873e3f01e2cfa3f23bc698290f2d68dda5f846d", Tag.CRASHING, Tag.BUGGY_PROJECT)
tag_manually("zune-image-zune-hdr-decode_buffer.wasm", "f873e3f01e2cfa3f23bc698290f2d68dda5f846d", Tag.CRASHING, Tag.BUGGY_PROJECT)

# [STDOUT] thread '<unnamed>' panicked at /projects/lewton/repo/src/header.rs:505:29:
# [STDOUT] capacity overflow
tag_manually("lewton-parse_ogg.wasm", "bb2955b717094b40260902cf2f8dd9c5ea62a84a", Tag.CRASHING)
# Heap OOB in ARMT_Convert?
tag_manually("lzma-7z.wasm", "d25e63d8f6b8186d04146cb19405bc5ad565412e", Tag.CRASHING)
# [STDOUT] thread '<unnamed>' panicked at /projects/regex/repo/regex-automata/src/dfa/dense.rs:4631:9:
# [STDOUT] index out of bounds: the len is 0 but the index is 1
tag_manually("regex-fuzz_regex_automata_deserialize_dense_dfa.wasm", "1a069b9232c607b34c4937122361aa075ef573fa", Tag.CRASHING)

# [STDOUT] thread '<unnamed>' panicked at fuzzers/canonicalize.rs:15:9:
# [STDOUT] assertion `left == right` failed
# [STDOUT]   left: [1, 0, 0, 128, 0, 0, 0, 0]
# [STDOUT]  right: [1, 0, 0, 0, 0, 0, 0, 0]
tag_manually("capnproto-rust-canonicalize.wasm", "fa4cea7fdc09dce522a1e71a5ef44309dee82d42", Tag.CRASHING)
# [STDOUT] thread '<unnamed>' panicked at /projects/comrak/repo/src/parser/mod.rs:3348:21:
# [STDOUT] assertion failed: (sp.end.column - sp.start.column + 1 == x) || rem == 0
tag_manually("comrak-fuzz_options.wasm", "886851a5ceeaafd20726643e529365225e70f433", Tag.CRASHING)
tag_manually("comrak-gfm_footnotes.wasm", "886851a5ceeaafd20726643e529365225e70f433", Tag.CRASHING)
tag_manually("comrak-quadratic.wasm", "886851a5ceeaafd20726643e529365225e70f433", Tag.CRASHING)
# [STDOUT] thread '<unnamed>' panicked at /projects/toml-edit/repo/crates/toml_edit/src/parser/inline_table.rs:160:18:
# [STDOUT] setting a value should set a prefix
tag_manually("toml-edit-toml_edit_fuzz-parse_document.wasm", "2923f5961d2ca977ced51fd784b6c8d64f01ee18", Tag.CRASHING)
# [STDOUT] thread '<unnamed>' panicked at fuzz_targets/compress.rs:27:5:
# [STDOUT] assertion `left == right` failed
# [STDOUT]   left: Ok
# [STDOUT]  right: DataError
tag_manually("zlib-rs-compress.wasm", "39838838ec2d49021548f90cec60cc3d8f56b188", Tag.CRASHING)
# [STDOUT] thread '<unnamed>' panicked at fuzz_targets/inflate_chunked.rs:51:5:
# [STDOUT] assertion `left == right` failed
# [STDOUT]   left: StreamEnd
# [STDOUT]  right: Ok
tag_manually("zlib-rs-inflate_chunked.wasm", "39838838ec2d49021548f90cec60cc3d8f56b188", Tag.CRASHING)


tag_manually("jsoncpp.wasm", "ca98c98457b1163cca1f7d8db62827c115fec6d1", Tag.CRASHING)

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

# This is the only harness with `LLVMFuzzerCustomMutator`. Our fuzzers don't
# support custom mutators currently.
tag_manually("x509-parser-x509_with_mutator.wasm", "a92bbab5cdc630f7d2c0410736bee55f0e3710e8", Tag.SKIP)

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
    # Skip explicitly ignored targets that shouldn't end up in the harness suite.
    if Tag.SKIP in t: continue

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

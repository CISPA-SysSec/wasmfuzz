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
    BROWSER = "browser"


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


def tag_browser(browser_harnesses):
    for harness, used_in in browser_harnesses.items():
        if not (harness_dir / (harness + ".wasm")).is_file():
            print("[WARN] missing harness from browser list:", harness)
            continue
        assert used_in.startswith(("chromium ", "firefox ")), harness
        tags[harness + ".wasm"].add(Tag.BROWSER)


# Harnesses that exercise code shipped in Chromium or Firefox. Each line points
# to the browser code that calls into the fuzzed library (paths relative to
# chromium/src and to the firefox tree, checked 2026-09-25). "not web" marks
# code that ships but doesn't consume web content.
tag_browser(
    {
        "brotli-decode": "chromium net/filter/brotli_source_stream.cc, firefox netwerk/streamconv/converters/nsHTTPCompressConv.cpp",
        "chromium-zlib-compress": "chromium third_party/blink/renderer/modules/compression/deflate_transformer.cc",
        "chromium-zlib-compression_utils_portable": "chromium third_party/zlib/google/compression_utils_portable.cc",
        "chromium-zlib-deflate": "chromium third_party/blink/renderer/modules/compression/deflate_transformer.cc",
        "chromium-zlib-inflate": "chromium third_party/blink/renderer/modules/compression/inflate_transformer.cc",
        "chromium-zlib-inflate_with_header": "chromium net/filter/gzip_source_stream.cc",
        "chromium-zlib-minizip_unzip": "chromium third_party/zlib/google/zip_reader.cc (not web)",
        "chromium-zlib-streaming_inflate": "chromium net/filter/gzip_source_stream.cc",
        "chromium-zlib-uncompress": "chromium third_party/zlib/google/compression_utils_portable.cc",
        "crabbyavif-decode": "chromium third_party/blink/renderer/platform/image-decoders/avif/avif_image_decoder.cc",
        "cssparser-color": "firefox servo/components/style/values/specified/color.rs",
        "cssparser-cssparser": "firefox servo/components/style/stylesheets/rule_parser.rs",
        "cssparser-nth": "firefox servo/components/selectors/parser.rs",
        "cssparser-rules": "firefox servo/components/style/stylesheets/rule_parser.rs",
        "cssparser-selectors": "firefox servo/components/selectors/parser.rs",
        "dav1d-decode": "chromium media/filters/dav1d_video_decoder.cc, firefox dom/media/platforms/agnostic/DAV1DDecoder.cpp",
        "encoding_rs-fuzz_encodings": "firefox parser/html/nsHtml5StreamParser.cpp, dom/encoding/TextDecoder.cpp",
        "encoding_rs-fuzz_labels": "firefox dom/encoding/TextDecoder.cpp",
        "encoding_rs-fuzz_mem": "firefox intl/encoding_glue/src/lib.rs (xpcom string conversions)",
        "encoding_rs-fuzz_roundtrip": "firefox intl/encoding_glue/src/lib.rs",
        "expat-xml_parse_UTF-8": "firefox parser/htmlparser/nsExpatDriver.cpp (RLBox), chromium skia/BUILD.gn (XMP, Android font config)",
        "expat-xml_parsebuffer_UTF-8": "firefox parser/htmlparser/nsExpatDriver.cpp (RLBox), chromium skia/BUILD.gn (XMP, Android font config)",
        "fdeflate-deflate": "chromium third_party/skia/src/encode/SkPngRustEncoderImpl.cpp",
        "fdeflate-inflate": "chromium third_party/skia/src/codec/SkPngRustCodec.cpp",
        "fdeflate-inflate_bytewise": "chromium third_party/skia/src/codec/SkPngRustCodec.cpp",
        "fdeflate-inflate_bytewise2": "chromium third_party/skia/src/codec/SkPngRustCodec.cpp",
        "fdeflate-inflate_bytewise3": "chromium third_party/skia/src/codec/SkPngRustCodec.cpp",
        "fdeflate-inflate_miniz": "chromium third_party/skia/src/codec/SkPngRustCodec.cpp",
        "fdeflate-inflate_split": "chromium third_party/skia/src/codec/SkPngRustCodec.cpp",
        "fdeflate-stored": "chromium third_party/skia/src/encode/SkPngRustEncoderImpl.cpp",
        "ffmpeg_DEMUXER": "chromium media/filters/ffmpeg_demuxer.cc",
        "ffmpeg_IO_DEMUXER": "chromium media/filters/ffmpeg_demuxer.cc",
        "firefox-fuzz_target_qcms": "firefox gfx/qcms (embedded ICC profiles, e.g. image/decoders/nsJPEGDecoder.cpp)",
        "firefox-prefreader": "firefox modules/libpref/parser (prefs.js, not web)",
        "flac-decoder": "chromium media/audio/flac_audio_handler.cc",
        "flac-seek": "chromium media/audio/flac_audio_handler.cc",
        "flate2-fuzz_deflate_decode": "chromium components/user_data_importer/utility/parsing_ffi/zip_archive.rs (via zip, not web)",
        "fontations-fuzz_basic_metadata": "chromium third_party/skia/src/ports/SkTypeface_fontations.cpp, firefox gfx/fontations_glue/lib.rs",
        "fontations-fuzz_name": "firefox gfx/fontations_glue/lib.rs (skrifa_font_get_preferred_name)",
        "fontations-fuzz_skrifa_charmap": "chromium third_party/skia/src/ports/SkTypeface_fontations.cpp, firefox gfx/fontations_glue/lib.rs",
        "fontations-fuzz_skrifa_color": "chromium third_party/skia/src/ports/SkTypeface_fontations.cpp",
        "fontations-fuzz_skrifa_outline": "chromium third_party/skia/src/ports/SkTypeface_fontations.cpp",
        "freetype2-ftfuzzer": "chromium third_party/skia/src/ports/SkFontHost_FreeType.cpp, firefox gfx/thebes/gfxFT2FontBase.cpp",
        "graphite-font": "firefox gfx/thebes/gfxGraphiteShaper.cpp (RLBox)",
        "graphite-segment": "firefox gfx/thebes/gfxGraphiteShaper.cpp (RLBox)",
        "harfbuzz-hb-shape": "chromium third_party/blink/renderer/platform/fonts/shaping/harfbuzz_shaper.cc, firefox gfx/thebes/gfxHarfBuzzShaper.cpp",
        "harfrust-fuzz_shape": "chromium third_party/blink/renderer/platform/fonts/shaping/harfbuzz_shaper.cc (HarfRustShaping feature)",
        "hunspell-affdicfuzzer": "firefox extensions/spellcheck/hunspell/glue/mozHunspell.cpp (RLBox; Chromium loads .bdic instead)",
        "icu-break_iterator": "chromium third_party/blink/renderer/platform/text/text_break_iterator.cc, v8/src/objects/js-segmenter.cc",
        "icu-calendar": "chromium v8/src/objects/js-date-time-format.cc, firefox intl/components/src/Calendar.cpp",
        "icu-collator_compare": "chromium v8/src/objects/js-collator.cc",
        "icu-converter": "chromium third_party/blink/renderer/platform/wtf/text/text_codec_icu.cc",
        "icu-date_format": "chromium v8/src/objects/js-date-time-format.cc, firefox intl/components/src/DateTimeFormat.cpp",
        "icu-date_time_pattern_generator": "chromium v8/src/objects/js-date-time-format.cc, firefox intl/components/src/DateTimePatternGenerator.cpp",
        "icu-decimal_format_symbols": "chromium v8/src/objects/js-number-format.cc, firefox intl/components/src/NumberFormat.cpp",
        "icu-dtfmtsym": "chromium v8/src/objects/js-date-time-format.cc, firefox intl/components/src/DateTimeFormat.cpp",
        "icu-idna": "chromium url/url_idna_icu.cc",
        "icu-list_format": "chromium v8/src/objects/js-list-format.cc, firefox intl/components/src/ListFormat.cpp",
        "icu-locale": "chromium v8/src/objects/js-locale.cc, firefox intl/components/src/Locale.cpp",
        "icu-locale_morph": "chromium v8/src/objects/js-locale.cc, firefox intl/components/src/Locale.cpp",
        "icu-normalizer2": "chromium v8/src/objects/intl-objects.cc (String.prototype.normalize)",
        "icu-number_format": "chromium v8/src/objects/js-number-format.cc, firefox intl/components/src/NumberFormat.cpp",
        "icu-number_formatter": "chromium v8/src/objects/js-number-format.cc, firefox intl/components/src/NumberFormat.cpp",
        "icu-plurrule": "chromium v8/src/objects/js-plural-rules.cc, firefox intl/components/src/PluralRules.cpp",
        "icu-relative_date_time_formatter": "chromium v8/src/objects/js-relative-time-format.cc, firefox intl/components/src/RelativeTimeFormat.cpp",
        "icu-spoof": "chromium components/url_formatter/spoof_checks/idn_spoof_checker.cc",
        "icu-time_zone_names": "chromium v8/src/objects/js-date-time-format.cc, firefox intl/components/src/TimeZone.cpp",
        "icu-timezone_create": "chromium v8/src/objects/js-date-time-format.cc, firefox intl/components/src/TimeZone.cpp",
        "icu-ubidi": "chromium third_party/blink/renderer/platform/text/bidi_paragraph.cc, firefox intl/components/src/Bidi.cpp",
        "icu-ucasemap": "chromium v8/src/objects/intl-objects.cc (toLocaleUpperCase)",
        "icu-uloc_canonicalize": "chromium v8/src/objects/js-locale.cc, firefox intl/components/src/Locale.cpp",
        "icu-uloc_for_language_tag": "chromium v8/src/objects/js-locale.cc, firefox intl/components/src/Locale.cpp",
        "icu-uloc_get_name": "chromium v8/src/objects/js-locale.cc, firefox intl/components/src/Locale.cpp",
        "icu-uloc_is_right_to_left": "chromium v8/src/objects/js-locale.cc, firefox intl/components/src/Locale.cpp",
        "icu-uloc_open_keywords": "chromium v8/src/objects/js-locale.cc, firefox intl/components/src/Locale.cpp",
        "icu4x-calendar_add": "chromium v8/src/objects/js-temporal-objects.cc (via temporal_rs), firefox intl/components/src/calendar/ICU4XCalendar.cpp",
        "icu4x-calendar_construction": "chromium v8/src/objects/js-temporal-objects.cc (via temporal_rs), firefox intl/components/src/calendar/ICU4XCalendar.cpp",
        "icu4x-calendar_until": "chromium v8/src/objects/js-temporal-objects.cc (via temporal_rs), firefox intl/components/src/calendar/ICU4XCalendar.cpp",
        "icu4x-casemap": "chromium base/i18n/case_conversion.cc",
        "icu4x-collator": "firefox js/src/builtin/intl/collator_glue/src/lib.rs",
        "icu4x-ixdtf": "chromium v8/src/objects/js-temporal-objects.cc (via temporal_rs)",
        "icu4x-locale": "chromium base/i18n/icubridge/icu_bridge.cc, firefox js/src/builtin/intl/locale_glue/src/lib.rs",
        "icu4x-normalizer_compare_self": "chromium base/i18n/icubridge/normalizer.cc, firefox js/src/builtin/normalizer_glue/src/lib.rs",
        "icu4x-properties": "firefox js/src/irregexp/properties_glue/src/lib.rs",
        "icu4x-segmenter": "firefox intl/lwbrk/Segmenter.cpp, js/src/builtin/intl/Segmenter.cpp",
        "image-png-buf_independent": "chromium third_party/skia/src/codec/SkPngRustCodec.cpp",
        "image-png-chromium_skia": "chromium third_party/skia/src/codec/SkPngRustCodec.cpp",
        "image-png-decode": "chromium third_party/skia/src/codec/SkPngRustCodec.cpp",
        "image-png-roundtrip": "chromium third_party/skia/src/encode/SkPngRustEncoderImpl.cpp",
        "jxl-rs-decode": "chromium third_party/blink/renderer/platform/image-decoders/jxl/jxl_image_decoder.cc, firefox image/decoders/nsJXLDecoder.cpp",
        "jxl-rs-decode_header": "chromium third_party/blink/renderer/platform/image-decoders/jxl/jxl_image_decoder.cc, firefox image/decoders/nsJXLDecoder.cpp",
        "libaom-av1_dec": "firefox dom/media/platforms/agnostic/AOMDecoder.cpp (dav1d is the default)",
        "libgav1-obu_parser": "chromium media/gpu/av1_decoder.cc",
        "libjpeg-turbo-compress": "chromium third_party/blink/renderer/platform/image-encoders/image_encoder.cc, firefox image/encoders/jpeg/nsJPEGEncoder.cpp",
        "libjpeg-turbo-decompress": "chromium third_party/blink/renderer/platform/image-decoders/jpeg/jpeg_image_decoder.cc, firefox image/decoders/nsJPEGDecoder.cpp",
        "libjpeg-turbo-decompress_libjpeg": "chromium third_party/blink/renderer/platform/image-decoders/jpeg/jpeg_image_decoder.cc, firefox image/decoders/nsJPEGDecoder.cpp",
        "libjpeg-turbo-decompress_yuv": "chromium third_party/blink/renderer/platform/image-decoders/jpeg/jpeg_image_decoder.cc",
        "libpng-read": "firefox image/decoders/nsPNGDecoder.cpp",
        "libsrtp-chromium": "chromium third_party/webrtc/pc/srtp_session.cc",
        "libsrtp-srtp": "chromium third_party/webrtc/pc/srtp_session.cc, firefox dom/media/webrtc/transport/SrtpFlow.cpp",
        "libvpx-dec-vp8": "chromium media/filters/vpx_video_decoder.cc, firefox dom/media/platforms/agnostic/VPXDecoder.cpp",
        "libvpx-dec-vp9": "chromium media/filters/vpx_video_decoder.cc, firefox dom/media/platforms/agnostic/VPXDecoder.cpp",
        "libwebp-advanced_api": "chromium third_party/blink/renderer/platform/image-decoders/webp/webp_image_decoder.cc, firefox image/decoders/nsWebPDecoder.cpp",
        "libwebp-advanced_api2": "chromium third_party/blink/renderer/platform/image-decoders/webp/webp_image_decoder.cc, firefox image/decoders/nsWebPDecoder.cpp",
        "libwebp-animation_api": "chromium third_party/blink/renderer/platform/image-decoders/webp/webp_image_decoder.cc, firefox image/decoders/nsWebPDecoder.cpp",
        "libwebp-animdecoder": "chromium third_party/blink/renderer/platform/image-decoders/webp/webp_image_decoder.cc, firefox image/decoders/nsWebPDecoder.cpp",
        "libwebp-dwebp": "chromium third_party/blink/renderer/platform/image-decoders/webp/webp_image_decoder.cc, firefox image/decoders/nsWebPDecoder.cpp",
        "libwebp-enc_dec": "chromium third_party/blink/renderer/platform/image-encoders/image_encoder.cc",
        "libwebp-mux_demux_api": "chromium third_party/blink/renderer/platform/image-decoders/webp/webp_image_decoder.cc, firefox image/decoders/nsWebPDecoder.cpp",
        "libwebp-simple_api": "chromium third_party/blink/renderer/platform/image-decoders/webp/webp_image_decoder.cc, firefox image/decoders/nsWebPDecoder.cpp",
        "libxml2-xml": "chromium third_party/blink/renderer/core/xml/parser/xml_document_parser.cc",
        "libxml2-xpath": "chromium third_party/blink/renderer/core/xml/xslt_processor_libxslt.cc",
        "libxslt-xpath": "chromium third_party/blink/renderer/core/xml/xslt_processor_libxslt.cc",
        "libxslt-xslt": "chromium third_party/blink/renderer/core/xml/xslt_processor_libxslt.cc",
        "lz4-compress": "firefox mozglue/static/Compression.cpp (startup cache, not web)",
        "lz4-compress_frame": "firefox mozglue/static/Compression.cpp (startup cache, not web)",
        "lz4-decompress": "firefox mozglue/static/Compression.cpp (startup cache, not web)",
        "lz4-decompress_frame": "firefox mozglue/static/Compression.cpp (startup cache, not web)",
        "miniz_oxide-inflate_nonwrapping": "chromium components/user_data_importer/utility/parsing_ffi/zip_archive.rs (via zip/flate2, not web)",
        "miniz_oxide-roundtrip": "chromium third_party/skia/src/encode/SkPngRustEncoderImpl.cpp (png crate via flate2)",
        "moxcms-icc_to_srgb": "chromium third_party/skia/rust/icc/FFI.rs",
        "moxcms-safe_read": "chromium third_party/skia/rust/icc/FFI.rs",
        "moxcms-safe_read_create": "chromium third_party/skia/rust/icc/FFI.rs",
        "moxcms-unsafe": "chromium third_party/skia/rust/icc/FFI.rs",
        "mp4parse-avif": "firefox image/decoders/nsAVIFDecoder.cpp",
        "mp4parse-mp4": "firefox dom/media/mp4/MP4Metadata.cpp",
        "nestegg-fuzz": "firefox dom/media/webm/WebMDemuxer.cpp",
        "openh264-decoder": "firefox dom/media/gmp (Cisco-built OpenH264 GMP plugin; Chromium ships only the encoder)",
        "opus-decode_fixed": "chromium third_party/webrtc/modules/audio_coding/codecs/opus/opus_interface.cc, firefox third_party/libwebrtc/modules/audio_coding/codecs/opus/opus_interface.cc",
        "opus-decode_float": "chromium media/filters/opus_audio_decoder.cc, firefox dom/media/ogg/OggCodecState.cpp",
        "opus-multistream_decode_fixed": "chromium third_party/webrtc/modules/audio_coding/codecs/opus/opus_interface.cc, firefox third_party/libwebrtc/modules/audio_coding/codecs/opus/opus_interface.cc",
        "opus-multistream_decode_float": "chromium media/filters/opus_audio_decoder.cc",
        "ots-sanitize": "chromium third_party/blink/renderer/platform/fonts/web_font_decoder.cc, firefox gfx/thebes/gfxUserFontSet.cpp",
        "serde_json-from_slice": "firefox dom/base/speculationrules/parser.rs",
        "sfv-parse_dictionary": "chromium net/http/structured_headers.cc, firefox netwerk/base/http-sfv/src/lib.rs",
        "sfv-parse_item": "chromium net/http/structured_headers.cc, firefox netwerk/base/http-sfv/src/lib.rs",
        "sfv-parse_list": "chromium net/http/structured_headers.cc, firefox netwerk/base/http-sfv/src/lib.rs",
        "sfv-reparse_dictionary": "chromium net/http/structured_headers.cc, firefox netwerk/base/http-sfv/src/lib.rs",
        "sfv-reparse_item": "chromium net/http/structured_headers.cc, firefox netwerk/base/http-sfv/src/lib.rs",
        "sfv-reparse_list": "chromium net/http/structured_headers.cc, firefox netwerk/base/http-sfv/src/lib.rs",
        "snappy-compress": "chromium third_party/leveldatabase/src/table/format.cc, firefox dom/indexedDB/ActorsParentCommon.cpp",
        "snappy-uncompress": "chromium third_party/leveldatabase/src/table/format.cc, firefox dom/indexedDB/ActorsParentCommon.cpp",
        "sqlite-ossfuzz": "chromium sql/database.cc, firefox storage/mozStorageConnection.cpp (not web)",
        "symphonia-decode_any": "chromium media/filters/symphonia_audio_decoder.cc",
        "symphonia-decode_flac": "chromium media/filters/symphonia_audio_decoder.cc",
        "symphonia-decode_mpa": "chromium media/filters/symphonia_audio_decoder.cc",
        "symphonia-decode_pcm": "chromium media/filters/symphonia_audio_decoder.cc",
        "symphonia-decode_vorbis": "chromium media/filters/symphonia_audio_decoder.cc",
        "symphonia-demux_flac": "chromium media/filters/symphonia_demuxer_bridge.rs",
        "symphonia-demux_isomp4": "chromium media/filters/symphonia_demuxer_bridge.rs",
        "symphonia-demux_mkv": "chromium media/filters/symphonia_demuxer_bridge.rs",
        "symphonia-demux_ogg": "chromium media/filters/symphonia_demuxer_bridge.rs",
        "symphonia-demux_wav": "chromium media/filters/symphonia_demuxer_bridge.rs",
        "temporal_rs-arithmetic": "chromium v8/src/objects/js-temporal-objects.cc",
        "temporal_rs-parse": "chromium v8/src/objects/js-temporal-objects.cc",
        "usrsctp-connect": "firefox netwerk/sctp/datachannel/DataChannelUsrsctp.cpp",
        "usrsctp-fragment": "firefox netwerk/sctp/datachannel/DataChannelUsrsctp.cpp",
        "usrsctp-listen": "firefox netwerk/sctp/datachannel/DataChannelUsrsctp.cpp",
        "vorbis-decode": "firefox dom/media/ogg/OggCodecState.cpp (header parsing only; decode goes through ffvpx)",
        "wgpu-ir": "firefox gfx/wgpu_bindings/src/server.rs (naga validator)",
        "wgpu-wgsl_parser": "firefox dom/webgpu/ShaderModule.cpp, gfx/wgpu_bindings/src/server.rs",
        "woff2-convert_woff2ttf": "chromium third_party/ots/src/src/ots.cc, firefox gfx/ots/src/ots.cc (RLBox)",
        "woff2-convert_woff2ttf_new_entry": "chromium third_party/ots/src/src/ots.cc, firefox gfx/ots/src/ots.cc (RLBox)",
        "wuffs-gif": "chromium third_party/skia/src/codec/SkWuffsCodec.cpp",
        "wuffs-pixel_swizzler": "chromium third_party/skia/src/codec/SkWuffsCodec.cpp (via the GIF decoder)",
        "zip2-zip2-read": "chromium components/user_data_importer/utility/parsing_ffi/zip_archive.rs, firefox toolkit/crashreporter/client/app/src/lang/zip.rs (not web)",
        "zlib-uncompress": "firefox netwerk/streamconv/converters/nsHTTPCompressConv.cpp",
        "zstd-decompress_dstSize_tooSmall": "chromium net/filter/zstd_source_stream.cc, firefox netwerk/streamconv/converters/nsHTTPCompressConv.cpp",
        "zstd-dictionary_decompress": "chromium net/filter/zstd_source_stream.cc (shared dictionaries)",
        "zstd-simple_decompress": "chromium net/filter/zstd_source_stream.cc, firefox netwerk/streamconv/converters/nsHTTPCompressConv.cpp",
        "zstd-stream_decompress": "chromium net/filter/zstd_source_stream.cc, firefox netwerk/streamconv/converters/nsHTTPCompressConv.cpp",
        "zune-image-zune-jpeg-decode_buffer": "chromium third_party/blink/renderer/platform/image-decoders/jpeg/jpeg_rust_image_decoder.cc (IsRustyJpegEnabled)",
        "zune-image-zune-jpeg-decode_incremental": "chromium third_party/blink/renderer/platform/image-decoders/jpeg/jpeg_rust_image_decoder.cc (IsRustyJpegEnabled)",
    }
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
    "graphite-font",
    "graphite-segment",
    "image-script_png",
    "image-script_jpeg", "image-script_tiff",
    "image-script_ico", # "image-script_webp", # "image-script_guess",
    "jxl-oxide-libfuzzer-decode", "jxl-rs-decode", "lcms-cms_transform_all",
    "libjxl-djxl",
    # "libarchive-ossfuzz", "libarchive-upstream", # TODO: OOMs with non-snapshot fuzzing
    "libpng-read",
    "libheif-box", "libheif-file",
    # "libsndfile",
    "libtiff-read_rgba",
    "libwebp-dwebp",
    # "openjpeg-opj_decompress_J2K",
    # "openjpeg-opj_decompress_JP2",
    "openssl-acert", # "openssl-crl",
    # "openssl-x509",
    # openthread? # jbig2dec? # mbedtls?
    # "quick-xml-fuzz_target_1",
    # "sqlite-ossfuzz",
    #"stb-png_read",
    "symphonia-decode_any",
    "vorbis-decode",
    "woff2-convert_woff2ttf",
    # "x509-parser-certreq",
    #"x509-parser-crl",
    "x509-parser-x509_parse",
    # "zune-image-zune-jpeg-decode_incremental",
    "image-script_webp",
    "libwebp-animdecoder",
    "libwebp-mux_demux_api",
    "lopdf-parse_pdf",
    "mbedtls-fuzz_server",
    "openjpeg-opj_decompress_JP2",
    "sqlite-ossfuzz",
    "stb-stbi_read",
    "symphonia-demux_isomp4",
    "symphonia-demux_mkv",
    # Note: these seem saturated in both lod and no-lod?
    # "zip2-zip2-read"
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

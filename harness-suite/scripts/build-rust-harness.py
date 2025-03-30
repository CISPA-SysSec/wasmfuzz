#!/usr/bin/env python3
import subprocess
import os
import shutil
import argparse
import tomllib
from pathlib import Path

# Note: Python's stdlib doesn't currently support writing TOML files
import tomlkit

parser = argparse.ArgumentParser()
parser.add_argument('--workdir', default='/projects/')
parser.add_argument('--debug-assertions', action='store_true')
parser.add_argument('--debug', action='store_true')
parser.add_argument('--small-stack', action='store_true')
parser.add_argument('--init-toolchain', action='store_true')
args = parser.parse_args()

RUSTUP_TOOLCHAIN = "nightly-2025-03-18"
TARGET_TRIPLE = "wasm32-wasip1"
WASI_SYSROOT = "/wasi-sdk/share/wasi-sysroot/"
CARGO = Path.home() / ".cargo" / "bin" / "cargo"
os.environ["RUSTUP_TOOLCHAIN"] = RUSTUP_TOOLCHAIN


def patch_cargo_toml(path):
    "switch project over to a custom `libfuzzer-sys` crate that supports building to WebAssembly modules"
    print(f"patching {path} for custom libfuzzer-sys")
    with open(path) as f:
        cargo_toml = tomlkit.load(f)
    deps = cargo_toml["dependencies"]
    deps["libfuzzer-sys"] = {
        "git": "https://github.com/Mrmaxmeier/libfuzzer",
        "rev": "b608dcf44c2071a54393cb92a2bc305a5e2a6799" # "target-wasm" branch
    }
    deps["arbitrary"] = {
        "git": "https://github.com/rust-fuzz/arbitrary.git",
        "rev": "ef80790c5bbcd24f342967e2388aa14f2c0d4a6b",
        "features": ["derive"]
    }
    # fix rare cases of remaining libfuzzer-sys dependencies (regalloc2)
    if "patch" not in cargo_toml:
        cargo_toml.add("patch", tomlkit.table())
        cargo_toml["patch"].add("crates-io", tomlkit.table())
    cargo_toml["patch"]["crates-io"]["libfuzzer-sys"] = deps["libfuzzer-sys"]
    cargo_toml["patch"]["crates-io"]["arbitrary"] = deps["arbitrary"]
    with open(path, "w") as f:
        tomlkit.dump(cargo_toml, f)


def build_folder(folder, verb="build"):
    env = os.environ.copy()
    if "CFLAGS" not in env:
        env["CFLAGS"] = f"--sysroot {WASI_SYSROOT}"
    env["PKG_CONFIG_SYSROOT_DIR"] = WASI_SYSROOT
    env["RUSTFLAGS"] = "-C target-feature=+crt-static"
    env["RUSTFLAGS"] = "-C target-cpu=lime1"
    env["RUSTFLAGS"] += " -Zwasi-exec-model=reactor"
    env["RUSTFLAGS"] += " --cfg=fuzzing"

    # https://github.com/rust-lang/rust/pull/126985
    env["RUSTFLAGS"] += " -Zembed-source=yes -Zdwarf-version=5 -g"

    env["CARGO_PROFILE_RELEASE_OPT_LEVEL"] = "s"
    env["CARGO_PROFILE_RELEASE_PANIC"] = "abort"
    env["CARGO_PROFILE_RELEASE_CODEGEN_UNITS"] = "1"
    env["CARGO_PROFILE_RELEASE_STRIP"] = "none"
    env["CARGO_PROFILE_RELEASE_DEBUG"] = "full"
    if args.debug_assertions:
        env["CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS"] = "true"
        env["CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS"] = "true"
    if args.small_stack:
        # default: 16 pages, 1MB
        #    smol: 1 page, 64kb
        env["RUSTFLAGS"] += f" -C link-arg=-zstack-size={1<<16}"
    # embed build-id (requires LLVM 17)
    env["RUSTFLAGS"] += " -C link-arg=--build-id"
    subprocess.run([
        CARGO, verb, "--bins", f"--target={TARGET_TRIPLE}",
        "-Z=build-std=std,panic_abort",
        "--profile=dev" if args.debug else "--profile=release"
    ], cwd=folder, env=env, check=True)


def init_toolchain():
    # Install Rust nightly toolchain with WASM support
    subprocess.run(f"curl --proto '=https' -sSf https://sh.rustup.rs/ | sh -s -- " \
                   f"-y --default-toolchain={RUSTUP_TOOLCHAIN} --target={TARGET_TRIPLE} " \
                   f"--profile minimal --component=rust-src", shell=True, check=True)

    # Prime crates.io registry with a sample build
    dir = Path("/tmp/sample")
    dir.mkdir()
    with open(dir / "Cargo.toml", "w") as f:
        f.write("""\
[package]
name = "sample-fuzz"
version = "0.0.0"
edition = "2021"
[dependencies]
libfuzzer-sys = "0.4.0"\
""")
    (dir / "src").mkdir()
    with open(dir / "src" / "main.rs", "w") as f:
        f.write("""#![no_main]\nlibfuzzer_sys::fuzz_target!(|_data: &[u8]| {});""")
    patch_cargo_toml(dir / "Cargo.toml")
    build_folder(dir, verb="check")
    shutil.rmtree(dir)

def is_cargo_fuzz_manifest(path):
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
        metadata = data.get("package", {}).get("metadata", {})
        return "cargo-fuzz" in metadata
    except tomllib.TOMLDecodeError as e:
        print(e)
        return False

def build_harnesses():
    OUT = Path("/out/")

    folders = [
        cargo_toml.parent
        for cargo_toml in Path(args.workdir).glob("**/Cargo.toml")
        if is_cargo_fuzz_manifest(cargo_toml)
    ]

    for folder in folders:
        print(f"{folder = }")
        patch_cargo_toml(f"{folder}/Cargo.toml")
        build_folder(folder)

        # find target folder (depends on workspace setup)
        folder_ = Path(folder)
        for _ in range(5):
            bins_path = folder_ / "target" / TARGET_TRIPLE
            if bins_path.exists(): break
            folder_ = folder_.parent
        bins_path /= "debug" if args.debug else "release"

        for wasm in bins_path.glob("*.wasm"):
            print(wasm)
            slug = wasm.parts[2]
            if "crates" in wasm.parts:
                slug += "-" + wasm.parts[wasm.parts.index("crates")+1]
            slug += "-" + wasm.stem.replace("-fuzzer", "").replace("_fuzzer", "")
            if args.debug:
                slug += "-dbg"
            shutil.copyfile(wasm, OUT / f"{slug}.wasm")
        # subprocess.run([CARGO, "clean"], cwd=folder, env=env)


if __name__ == "__main__":
    if args.init_toolchain:
        init_toolchain()
    else:
        build_harnesses()

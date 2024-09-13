#!/usr/bin/env python3
import subprocess
import os
import shutil
import argparse
from pathlib import Path


parser = argparse.ArgumentParser()
parser.add_argument('--workdir', default='/projects/')
parser.add_argument('--debug-assertions', action='store_true')
parser.add_argument('--debug', action='store_true')
parser.add_argument('--small-stack', action='store_true')
parser.add_argument('--init-toolchain', action='store_true')
args = parser.parse_args()

WASM_V2 = True
RUSTUP_TOOLCHAIN = "nightly-2024-08-28"
TARGET_TRIPLE = "wasm32-wasip1"
WASI_SYSROOT = "/wasi-sdk/share/wasi-sysroot/"
CARGO = Path.home() / ".cargo" / "bin" / "cargo"
os.environ["RUSTUP_TOOLCHAIN"] = RUSTUP_TOOLCHAIN


def patch_cargo_toml(path):
    "switch project over to a custom `libfuzzer-sys` crate that supports building to WebAssembly modules"
    # TODO: this is incredibly crude, but python's stdlib doesn't currently ship a toml writer (3.12)
    print(f"patching {path} for custom libfuzzer-sys")
    with open(path) as f:
        cargo_toml = f.read()
    if "[dependencies.libfuzzer-sys]\n" in cargo_toml:
        lines = cargo_toml.splitlines()
        i = lines.index("[dependencies.libfuzzer-sys]")
        j = lines.index("", i)
        cargo_toml = '\n'.join(lines[:i] + lines[j:])
    del_lines = ["dependencies.libfuzzer-sys", "libfuzzer-sys =", "arbitrary ="]
    cargo_toml = '\n'.join(x for x in cargo_toml.splitlines() if not any(y in x for y in del_lines))
    cargo_toml += "\n"
    cargo_toml += "\n"
    cargo_toml += "[dependencies.arbitrary]\n"
    cargo_toml += "git = \"https://github.com/rust-fuzz/arbitrary.git\"\n"
    cargo_toml += "features = [\"derive\"]\n"
    cargo_toml += "\n"
    cargo_toml += "[dependencies.libfuzzer-sys]\n"
    cargo_toml += "git = \"https://github.com/Mrmaxmeier/libfuzzer\"\n"
    cargo_toml += "branch = \"target-wasm\"\n"
    cargo_toml += "\n"
    cargo_toml += "[patch.crates-io]\n" # fix rare cases of remaining libfuzzer-sys dependencies (regalloc2)
    cargo_toml += 'libfuzzer-sys = { git = "https://github.com/Mrmaxmeier/libfuzzer", branch = "target-wasm" }\n'
    cargo_toml += 'arbitrary = { git = "https://github.com/rust-fuzz/arbitrary.git", features = ["derive"] }\n'
    with open(path, "w") as f:
        f.write(cargo_toml)


def build_folder(folder, verb="build"):
    env = os.environ.copy()
    if "CFLAGS" not in env:
        env["CFLAGS"] = f"--sysroot {WASI_SYSROOT}"
    env["PKG_CONFIG_SYSROOT_DIR"] = WASI_SYSROOT
    env["RUSTFLAGS"] = "-C target-feature=+crt-static"
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
    if WASM_V2:
        # rustc --print target-features --target=wasm32-wasip1
        # env["RUSTFLAGS"] += " -C target-feature=+bulk-memory,+mutable-globals,+nontrapping-fptoint,+sign-ext"
        env["RUSTFLAGS"] += " -C target-feature=+bulk-memory,+nontrapping-fptoint,+sign-ext"
        # env["RUSTFLAGS"] += " -C target-feature=+multivalue"
        # https://github.com/rust-lang/rust/issues/83940
    if args.small_stack:
        # default: 16 pages, 1MB
        #    smol: 1 page, 64kb
        env["RUSTFLAGS"] += f" -C link-arg=-zstack-size={1<<16}"
    # embed build-id (requires LLVM 17)
    env["RUSTFLAGS"] += f" -C link-arg=--build-id"
    subprocess.run([
        CARGO, verb, "--bins", f"--target={TARGET_TRIPLE}",
        f"-Z=build-std=std,panic_abort", "--profile=dev" if args.debug else "--profile=release"
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


def build_harnesses():
    OUT = Path("/out/")

    folders = [
        cargo_toml.parent
        for cargo_toml in Path(args.workdir).glob("**/Cargo.toml")
        if "cargo-fuzz = true" in open(cargo_toml, "r").read()
    ]

    for folder in folders:
        print(f"{folder = }")

        with open(f"{folder}/Cargo.toml") as f:
            data = f.read()
            if "libfuzzer-sys" not in data:
                print("[!] doesn't appear to be a cargo-fuzz harness")
                continue

        patch_cargo_toml(f"{folder}/Cargo.toml")
        build_folder(folder)

        bins_path = Path(folder) / "target" / TARGET_TRIPLE
        bins_path /= "debug" if args.debug else "release"
        for wasm in bins_path.glob("*.wasm"):
            print(wasm)
            slug = wasm.parts[2] + "-" + wasm.stem.replace("-fuzzer", "").replace("_fuzzer", "")
            if args.debug:
                slug += "-dbg"
            shutil.copyfile(wasm, OUT / f"{slug}.wasm")
        # subprocess.run([CARGO, "clean"], cwd=folder, env=env)


if __name__ == "__main__":
    if args.init_toolchain:
        init_toolchain()
    else:
        build_harnesses()

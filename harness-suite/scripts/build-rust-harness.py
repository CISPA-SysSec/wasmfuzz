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
parser.add_argument('--large-stack', action='store_true')
parser.add_argument('--init-toolchain', action='store_true')
args = parser.parse_args()

BUILD_TYPE = os.environ.get("BUILD_TYPE", "wasi-lime1")
assert BUILD_TYPE in ["wasi-lime1", "wasi-mvp", "x86_64-libfuzzer"]
BUILD_FLAGS = os.environ.get("BUILD_FLAGS", "").split(";")
RUSTUP_TOOLCHAIN = "nightly-2025-07-26"
WASI_SYSROOT = "/wasi-sdk/share/wasi-sysroot/"
CARGO = Path.home() / ".cargo" / "bin" / "cargo"
os.environ["RUSTUP_TOOLCHAIN"] = RUSTUP_TOOLCHAIN
if BUILD_TYPE == "x86_64-libfuzzer":
    TARGET_TRIPLE = "x86_64-unknown-linux-gnu"
else:
    TARGET_TRIPLE = "wasm32-wasip1"


def patch_cargo_toml(path):
    "switch project over to a custom `libfuzzer-sys` crate that supports building to WebAssembly modules"
    print(f"patching {path} for custom libfuzzer-sys")
    with open(path) as f:
        cargo_toml = tomlkit.load(f)

    libfuzzer_sys_dep = {
        "git": "https://github.com/Mrmaxmeier/libfuzzer",
        "rev": "b608dcf44c2071a54393cb92a2bc305a5e2a6799", # "target-wasm" branch
        "features": ["arbitrary-derive"],
    }
    # This contains PR #181 (282cc87277d9aab93bcbe154b136625d66ddd1a6)
    arbitrary_dep = {
        "version": "1.4.1",
        "features": ["derive"]
    }
    if "arbitrary-simple-encoding" in BUILD_FLAGS:
        # Note: "simple-encoding" is actually more difficult to solve
        # for non-grammar-aware fuzzers
        arbitrary_dep = {
            "git": "https://github.com/Mrmaxmeier/arbitrary.git",
            "rev": "7a98f5970df24501866c3f2aa0ec49649731c18f",
            "features": ["derive", "simple-encoding"]
        }

    def make_inline(x: dict):
        # Ref: https://github.com/python-poetry/tomlkit/issues/414
        if True:
            return x
        res = tomlkit.inline_table()
        res.update(x)
        return res

    if "dependencies" in cargo_toml:
        deps = cargo_toml["dependencies"]
    elif "dependencies" in cargo_toml.get("workspace", {}):
        deps = cargo_toml["workspace"]["dependencies"]
    else:
        return

    def replace_dep(name, dep, add_if_missing=False):
        if name not in deps and not add_if_missing:
            return
        was_optional = name in deps and not isinstance(deps[name], str) and deps[name].get("optional", None)
        if name in deps and not isinstance(deps[name], str):
            deps[name].update(dep)
            for k in list(deps[name].keys()):
                if k not in dep:
                    del deps[name][k]
        else:
            deps.update({name: make_inline(dep)})
        if was_optional is not None:
            deps[name]["optional"] = was_optional

    replace_dep("libfuzzer-sys", libfuzzer_sys_dep)
    replace_dep("arbitrary", arbitrary_dep, add_if_missing="arbitrary-simple-encoding" in BUILD_FLAGS)

    # Fix rare cases of remaining deps-of-deps
    if "patch" not in cargo_toml:
        cargo_toml.update({"patch": tomlkit.table()})
        cargo_toml["patch"].update({"crates-io": tomlkit.table()})
    # Note: patch mechanism doesn't support injecting feautres. This should be fine for us though.
    cargo_toml["patch"]["crates-io"]["libfuzzer-sys"] = make_inline(libfuzzer_sys_dep)
    del cargo_toml["patch"]["crates-io"]["libfuzzer-sys"]["features"]
    if "git" in arbitrary_dep:
        cargo_toml["patch"]["crates-io"]["arbitrary"] = make_inline(arbitrary_dep)
        del cargo_toml["patch"]["crates-io"]["arbitrary"]["features"]
    with open(path, "w") as f:
        tomlkit.dump(cargo_toml, f)


def build_folder(folder, verb="build"):
    env = os.environ.copy()
    env["RUSTFLAGS"] = "--cfg=fuzzing"
    if BUILD_TYPE == "x86_64-libfuzzer":
        # https://github.com/rust-fuzz/cargo-fuzz/blob/65e3279c9602375037cb3aaabd3209c5b746375c/src/project.rs#L175-L191
        env["RUSTFLAGS"] += " -Cpasses=sancov-module" \
                            " -Cllvm-args=-sanitizer-coverage-level=4" \
                            " -Cllvm-args=-sanitizer-coverage-inline-8bit-counters" \
                            " -Cllvm-args=-sanitizer-coverage-pc-table" \
                            " -Cllvm-args=-sanitizer-coverage-trace-compares" \
                            " -Cllvm-args=-sanitizer-coverage-stack-depth"
    else:
        # https://github.com/rust-lang/rust/pull/126985
        env["RUSTFLAGS"] += " -Zembed-source=yes -Zdwarf-version=5 -g"

        if "CFLAGS" not in env:
            env["CFLAGS"] = f"--sysroot {WASI_SYSROOT}"
        env["PKG_CONFIG_SYSROOT_DIR"] = WASI_SYSROOT
        env["RUSTFLAGS"] += " -C target-feature=+crt-static"
        target_cpu = {"wasi-lime1": "lime1", "wasi-mvp": "mvp"}[BUILD_TYPE]
        env["RUSTFLAGS"] += f" -C target-cpu={target_cpu}"
        env["RUSTFLAGS"] += " -Zwasi-exec-model=reactor"


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
    elif args.large_stack:
        #   large: 256 pages, 16MB
        env["RUSTFLAGS"] += f" -C link-arg=-zstack-size={16<<20}"

    if BUILD_TYPE != "x86_64-libfuzzer":
        # embed build-id into WASM module (requires LLVM 17)
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
        for parent in Path(folder).parents:
            cargo_toml = parent / "Cargo.toml"
            if cargo_toml.exists():
                patch_cargo_toml(cargo_toml)
        build_folder(folder)

        # find target folder (depends on workspace setup)
        folder_ = Path(folder)
        bins_path = None
        for _ in range(5):
            bins_path = folder_ / "target" / TARGET_TRIPLE
            if bins_path.exists(): break
            folder_ = folder_.parent
        assert bins_path is not None
        bins_path /= "debug" if args.debug else "release"

        for module in bins_path.glob("*"):
            if not (module.is_file() and os.access(module, os.X_OK)):
                continue
            print(module)
            slug = module.parts[2]
            if "crates" in module.parts:
                slug += "-" + module.parts[module.parts.index("crates")+1]
            slug += "-" + module.stem.replace("fuzzer_", "fuzzer-").replace("-fuzzer", "").replace("_fuzzer", "")
            if args.debug:
                slug += "-dbg"

            if BUILD_TYPE == "x86_64-libfuzzer":
                shutil.copyfile(module, OUT / f"{slug}.exe")
                os.chmod(OUT / f"{slug}.exe", 0o755)
            else:
                shutil.copyfile(module, OUT / f"{slug}.wasm")
        # subprocess.run([CARGO, "clean"], cwd=folder, env=env)


if __name__ == "__main__":
    if args.init_toolchain:
        init_toolchain()
    else:
        build_harnesses()

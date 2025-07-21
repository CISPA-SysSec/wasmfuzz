#!/usr/bin/env python3
from pathlib import Path
import sys
import subprocess
import shutil
import os

assert sys.argv[1:], "USAGE: make-one.py projects-x/y"
proj_path = Path(sys.argv[1])
build_type = sys.argv[2] if len(sys.argv) > 2 else "wasi-lime1"
build_flags = os.environ.get("BUILD_FLAGS", "foo;bar")
name = proj_path.stem
tag = f"wasmfuzz-bld-{name}-{build_type}"
cid = f"{tag}-extract"

PODMAN = os.environ.get("PODMAN", "podman" if shutil.which("podman") else "docker")

subprocess.run([
    PODMAN, "build",
    "-t", tag, ".",
    "--build-arg", f"project_name={name}",
    "--build-arg", f"project_path={proj_path}",
    "--build-arg", f"build_type={build_type}",
    "--build-arg", f"build_flags={build_flags}",
] + ([
    "--cache-ttl=336h",
] if PODMAN == "podman" else []), check=True)
subprocess.run([PODMAN, "create", "--name", cid, tag, "sh"], check=True)
subprocess.run([PODMAN, "cp", f"{cid}:/out", "./"], check=True)
subprocess.run([PODMAN, "rm", cid])

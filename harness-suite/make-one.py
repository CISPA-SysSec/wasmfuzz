#!/usr/bin/env python3
from pathlib import Path
import sys
import subprocess
import shutil
import os

assert sys.argv[1:], "USAGE: make-one.py projects-x/y"
proj_path = Path(sys.argv[1])
name = proj_path.stem
tag = f"wasmfuzz-builder-{name}"
cid = f"{tag}-extract"

PODMAN = os.environ.get("PODMAN", "podman" if shutil.which("podman") else "docker")

subprocess.run([
    PODMAN, "build",
    "-t", tag, ".",
    "--build-arg", f"project_name={name}",
    "--build-arg", f"project_path={proj_path}",
] + ([
    "--cache-ttl=336h",
] if PODMAN == "podman" else []), check=True)
subprocess.run([PODMAN, "create", "--name", cid, tag, "sh"], check=True)
subprocess.run([PODMAN, "cp", f"{cid}:/out", "./"], check=True)
subprocess.run([PODMAN, "rm", cid])


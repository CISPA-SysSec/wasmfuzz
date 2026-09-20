#!/usr/bin/env python3
import functools
import re
import subprocess
from pathlib import Path
import argparse
import csv
import io

parser = argparse.ArgumentParser()
parser.add_argument('--suite-dir', default="./")
parser.add_argument('--only-target', default=None)
parser.add_argument('--ignore-target', default=[
    "libwebp", # we target a known-buggy revision of libwebp
    "libpng", # upstream libpng broke their harness setup (May 2026)
], action='append')
parser.add_argument('--build', action='store_true')
parser.add_argument('--git-add', action='store_true')
parser.add_argument('--skip-update', action='store_true')
parser.add_argument('--skip-unmodified', action='store_true')
parser.add_argument('--from-prepare', action='store_true',
                    help="also bump projects that have no built module in out/, "
                         "by parsing their prepare.sh")

args = parser.parse_args()
harness_dir = Path(args.suite_dir) / "out"
assert harness_dir.exists()

@functools.cache
def get_remote_head(remote: str):
    return subprocess.check_output([
        "git", "ls-remote", remote, "HEAD"
    ]).decode().split()[0]


CLONE_RE = re.compile(
    r'^\s*git clone-rev\.sh\s+(?P<url>\S+)\s+(?P<path>\S+)\s+(?P<rev>[0-9a-f]{40})',
    re.M,
)


def project_dirs(suite_dir):
    dirs = []
    for group in ("projects-clike", "projects-rust"):
        base = Path(suite_dir) / group
        if base.exists():
            dirs += sorted(x for x in base.iterdir() if (x / "prepare.sh").exists())
    return dirs


def update_from_prepare(proj_dir):
    """Bump every pinned revision named in prepare.sh to its remote HEAD.

    suite-update.py normally reads the pins out of the git-metadata.csv section of
    the built modules in out/. Projects that currently build no module at all are
    invisible that way, so fall back to parsing prepare.sh directly.
    """
    prepare = proj_dir / "prepare.sh"
    text = prepare.read_text()
    changed = []
    for m in CLONE_RE.finditer(text):
        try:
            head = get_remote_head(m.group("url"))
        except subprocess.CalledProcessError as e:
            print("    !!", m.group("url"), e)
            continue
        if head and head != m.group("rev"):
            changed.append((m.group("url"), m.group("rev"), head))
    for url, old, head in changed:
        text = text.replace(old, head)
    if changed:
        prepare.write_text(text)
    return changed


if not args.skip_update:
    print("Updating revisions ...")
for harness in harness_dir.glob("*.wasm"):
    if args.skip_update:
        continue
    if args.only_target is not None and args.only_target not in harness.name:
        continue
    if any(x in harness.name for x in args.ignore_target):
        continue
    print(harness)

    try:
        git_metadata = subprocess.check_output(["llvm-objcopy", "--dump-section", "git-metadata.csv=-", harness])
    except Exception as e:
        print(e)
        continue

    git_metadata = io.StringIO(git_metadata.decode())
    reader = csv.DictReader(git_metadata)
    for row in reader:
        head = get_remote_head(row["origin"])
        path = Path(row["path"]).parts[2]
        proj_dirs = Path(args.suite_dir).glob("*/" + path)
        proj_dirs = [x for x in proj_dirs if "corpus" not in x.parts]
        assert len(proj_dirs) == 1, f"{proj_dirs=} {path=}"
        proj_dir = proj_dirs[0]
        if row["pinrev"] != head:
            print("[-]", row["origin"])
            with open(proj_dir / "prepare.sh", "r") as f:
                prepare_sh = f.read()
            prepare_sh = prepare_sh.replace(row["pin"], head)
            with open(proj_dir / "prepare.sh", "w") as f:
                f.write(prepare_sh)
        else:
            print("[+]", row["origin"])


if args.from_prepare and not args.skip_update:
    print("Updating revisions of projects without a built module ...")
    seen = set()
    for harness in harness_dir.glob("*.wasm"):
        try:
            md = subprocess.check_output(
                ["llvm-objcopy", "--dump-section", "git-metadata.csv=-", harness])
        except Exception:
            continue
        for row in csv.DictReader(io.StringIO(md.decode())):
            seen.add(Path(row["path"]).parts[2])
    for proj_dir in project_dirs(args.suite_dir):
        if proj_dir.name in seen:
            continue
        if args.only_target is not None and args.only_target not in proj_dir.name:
            continue
        if any(x in proj_dir.name for x in args.ignore_target):
            continue
        changed = update_from_prepare(proj_dir)
        print(("[-] " if changed else "[+] ") + str(proj_dir))
        for url, old, new in changed:
            print(f"      {url} {old[:12]} -> {new[:12]}")

stale_patch = []

build_failed = []

if args.build:
    print("Building projects ...")
    project_dirs = list(Path("projects-clike").iterdir()) + list(Path("projects-rust").iterdir())
    for proj_dir in project_dirs:
        # check if folder is git modified
        try:
            git_status = subprocess.check_output(
                ["git", "status", "--porcelain", str(proj_dir)]
            ).decode().strip()
            is_git_modified = bool(git_status)
        except Exception as e:
            print(f"Error checking git status for {proj_dir}: {e}")
            is_git_modified = True

        if not is_git_modified and args.skip_unmodified:
            print(f"-> {proj_dir} (not modified)")
            continue

        print(f"-> {proj_dir} ...")
        try:
            _output = subprocess.check_output(
                ["make", f"{proj_dir}/"],
                stderr=subprocess.STDOUT
            )
            if args.git_add:
                subprocess.check_output(["git", "add", str(proj_dir)])
        except subprocess.CalledProcessError as e:
            output = e.output.decode()
            if "patch does not apply" in output:
                stale_patch.append(proj_dir)
            else:
                build_failed.append(proj_dir)
            print()
            print(f"Build failed for {proj_dir}: Last 20 lines:")
            print("--------------------------------")
            print('\n'.join(output.splitlines()[-20:]))

    if stale_patch or build_failed:
        print("Build failed for the following projects:")
        for proj_dir in stale_patch:
            print(f"  - {proj_dir} (stale patch)")
        for proj_dir in build_failed:
            print(f"  - {proj_dir}")
    else:
        print("All builds succeeded!")

import enum
import tomllib
import subprocess
from pprint import pprint
from pathlib import Path
from collections import Counter

import requests

REPO_CACHE = Path("/tmp/crates-repo-cache")
REPO_CACHE.mkdir(parents=True, exist_ok=True)
PROJECTS_DIR = Path("projects-rust-wip")
PROJECTS_DIR.mkdir(parents=True, exist_ok=True)


class Feature(enum.Enum):
    HAS_CARGO_TOMLS = "has-cargo-tomls"
    ARBITRARY = "arbitrary"
    LIBFUZZER = "libfuzzer"
    AFLRS = "aflrs"
    CARGOFUZZ = "cargo-fuzz"
    ANY_FUZZING = "any-fuzzing"
    FUZZ_TARGETS_DIR = "fuzz-targets-dir"

def slugify(text):
    return text.lower().replace(" ", "-").replace("/", "-").replace(":", "-").strip("-")

features_ctr = Counter()

def process_repo(repo_path):
    flags = set()
    def flag(feature, cond):
        if cond:
            flags.add(feature)
    for toml in repo_path.glob("**/Cargo.toml"):
        with open(toml, "rb") as f:
            try:
                data = tomllib.load(f)
            except tomllib.TOMLDecodeError as e:
                print(toml, e)
                continue
        dependencies = data.get("dependencies", {})
        metadata = data.get("package", {}).get("metadata", {})
        flag(Feature.ARBITRARY, "arbitrary" in dependencies)
        flag(Feature.LIBFUZZER, "libfuzzer-sys" in dependencies)
        flag(Feature.AFLRS, "afl" in dependencies)
        flag(Feature.CARGOFUZZ, "cargo-fuzz" in metadata)
    flag(Feature.FUZZ_TARGETS_DIR, list(repo_path.glob("**/fuzz_targets")) != [])
    flag(Feature.HAS_CARGO_TOMLS, list(repo_path.glob("**/Cargo.toml")) != [])
    flag(Feature.ANY_FUZZING, any(x in flags for x in [Feature.LIBFUZZER, Feature.AFLRS, Feature.CARGOFUZZ]))
    features_ctr.update(flags)
    return flags


def process(crate):
    repo_url = crate["repository"]
    if not repo_url:
        print("[-] no repository url found for crate", crate["name"])
        return
    if "/tree/" in repo_url:
        repo_url = repo_url[:repo_url.index("/tree/")]
    repo_path = REPO_CACHE / slugify(repo_url)
    repo_slug = slugify(repo_url.replace("https://github.com/", ""))
    if not repo_path.exists():
        subprocess.run(["git", "clone", repo_url, repo_path, "--depth", "1"])
    elif False:
        subprocess.run(["git", "pull"], cwd=repo_path)

    features = process_repo(repo_path)
    if not features:
        print("[-] no features found for crate", crate["name"])
        return
    print(repo_path)
    print(features)

    if Feature.CARGOFUZZ not in features:
        return


    repo_rev = subprocess.check_output([
        "git", "rev-parse", "HEAD"
    ], cwd=repo_path).decode().strip()

    proj_dir = PROJECTS_DIR / repo_slug
    proj_dir.mkdir(parents=True, exist_ok=True)
    with open(proj_dir / "build.sh", "w") as f:
        f.write("""#!/bin/bash
set -e +x
source set-buildflags.sh
build-rust-harness.py""")

    with open(proj_dir / "prepare.sh", "w") as f:
        f.write(f"""#!/bin/bash
set -e +x
git clone-rev.sh {repo_url} {proj_dir.stem} {repo_rev}""")

    (proj_dir / "build.sh").chmod(0o755)
    (proj_dir / "prepare.sh").chmod(0o755)



for i in range(10):
    # url = f"https://crates.io/api/v1/crates?page={i+1}&per_page=50&sort=recent-downloads"
    url = f"https://crates.io/api/v1/crates?page={i+1}&per_page=50&sort=downloads"
    response = requests.get(url)
    data = response.json()
    for crate in data["crates"]:
        process(crate)

    print("features:")
    pprint(features_ctr)

import functools
import subprocess
from pathlib import Path
import argparse
import csv
import io

parser = argparse.ArgumentParser()
parser.add_argument('--suite-dir', default="./")

args = parser.parse_args()
harness_dir = Path(args.suite_dir) / "out"
assert harness_dir.exists()

@functools.cache
def get_remote_head(remote: str):
    return subprocess.check_output([
        "git", "ls-remote", remote, "HEAD"
    ]).decode().split()[0]

for harness in harness_dir.glob("*.wasm"):
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
        proj_dirs = list(Path(args.suite_dir).glob("*/" + path))
        assert len(proj_dirs) == 1, f"{proj_dirs=} {path=}"
        proj_dir = proj_dirs[0]
        if row["pinrev"] != head:
            print("[-]", row["origin"])
            with open(proj_dir / "prepare.sh") as f:
                prepare_sh = f.read()
            prepare_sh = prepare_sh.replace(row["pin"], head)
            with open(proj_dir / "prepare.sh", "w") as f:
                f.write(prepare_sh)
        else:
            print("[+]", row["origin"])

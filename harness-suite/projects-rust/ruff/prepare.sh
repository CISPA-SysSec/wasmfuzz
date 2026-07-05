set -e
git clone-rev.sh https://github.com/astral-sh/ruff.git "$PROJECT/repo" d5163c94b76cc3ab3643cab6bf2eb7e864e8bff7
git -C "$PROJECT/repo" apply "$PROJECT/crude-disable-zstd.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-harness-crashes.patch"

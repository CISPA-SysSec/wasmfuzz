set -e
git clone-rev.sh https://github.com/astral-sh/ruff.git "$PROJECT/repo" aa63c24b8f4a82f5f54dc90c4e6b5adadbf3e1b2
git -C "$PROJECT/repo" apply "$PROJECT/crude-disable-zstd.patch"

set -e
git clone-rev.sh https://github.com/astral-sh/ruff.git "$PROJECT/repo" 11b551c2befa7d9a8f4650b41794d9ea265ddc23
git -C "$PROJECT/repo" apply "$PROJECT/crude-disable-zstd.patch"

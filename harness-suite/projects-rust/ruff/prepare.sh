set -e
git clone-rev.sh https://github.com/astral-sh/ruff.git "$PROJECT/repo" 01695513ce33f1f1615309323ba145c42f4720c1
git -C "$PROJECT/repo" apply "$PROJECT/crude-disable-zstd.patch"

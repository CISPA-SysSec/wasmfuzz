set -e
git clone-rev.sh https://github.com/astral-sh/ruff.git "$PROJECT/repo" a16e82b1324459e9707a1d349527a0a3ccfebe37
git -C "$PROJECT/repo" apply "$PROJECT/crude-disable-zstd.patch"

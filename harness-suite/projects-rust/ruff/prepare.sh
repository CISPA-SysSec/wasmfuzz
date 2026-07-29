set -e
git clone-rev.sh https://github.com/astral-sh/ruff.git "$PROJECT/repo" 34d0944f3b1d0ce51db6a583e17faeb933df9be6
git -C "$PROJECT/repo" apply "$PROJECT/crude-disable-zstd.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-harness-crashes.patch"

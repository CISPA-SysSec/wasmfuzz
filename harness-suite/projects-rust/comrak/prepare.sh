set -e
git clone-rev.sh https://github.com/kivikakk/comrak.git "$PROJECT/repo" 886851a5ceeaafd20726643e529365225e70f433
git -C "$PROJECT/repo" apply "$PROJECT/fix-harnesses.patch"

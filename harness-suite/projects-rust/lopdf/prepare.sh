set -e
git clone-rev.sh https://github.com/J-F-Liu/lopdf.git "$PROJECT/repo" de506fae829fc25dd375ccf51d41162cbf057345
git -C "$PROJECT/repo" apply "$PROJECT/0001-cargo-fuzz.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-page-tree-size-hint.patch"

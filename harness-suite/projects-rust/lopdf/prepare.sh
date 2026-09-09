set -e
git clone-rev.sh https://github.com/J-F-Liu/lopdf.git "$PROJECT/repo" a62854e1bbea308cd7db6e34492c0b3873711471
git -C "$PROJECT/repo" apply "$PROJECT/0001-cargo-fuzz.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-page-tree-size-hint.patch"

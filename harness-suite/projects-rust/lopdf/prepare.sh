set -e
git clone-rev.sh https://github.com/J-F-Liu/lopdf.git "$PROJECT/repo" 0e781ce05f083330ecc24ac8c67833fbd076e7a2
git -C "$PROJECT/repo" apply "$PROJECT/port-cargo-fuzz.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-page-tree-size-hint.patch"

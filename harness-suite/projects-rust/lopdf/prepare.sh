set -e
git clone-rev.sh https://github.com/J-F-Liu/lopdf.git "$PROJECT/repo" 8e4a183d78eacb1b11919e56714c087a3fa44d93
git -C "$PROJECT/repo" apply "$PROJECT/port-cargo-fuzz.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-page-tree-size-hint.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-stream-end-overflow.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-brotli-reject-large-window.patch"

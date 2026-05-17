set -e
git clone-rev.sh https://github.com/etemesi254/zune-image "$PROJECT/repo" 26797e76c1448f3df6fe7e74df341fef7f5dc291
git -C "$PROJECT/repo" apply "$PROJECT/wasm.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-zune-crashes.patch"
git -C "$PROJECT/repo" apply "$PROJECT/decode-incremental-fuzz-wasm-cap.patch"


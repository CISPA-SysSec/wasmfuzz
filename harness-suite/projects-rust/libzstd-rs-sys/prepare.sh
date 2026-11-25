set -e
git clone-rev.sh https://github.com/trifectatechfoundation/libzstd-rs-sys "$PROJECT/repo" b9878d6f8bdf61ad84228d15dd671725d5a124ac
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-wasm-skip-c-oracle.patch"
git -C "$PROJECT/repo" apply "$PROJECT/port-nightly-allocator-api.patch"

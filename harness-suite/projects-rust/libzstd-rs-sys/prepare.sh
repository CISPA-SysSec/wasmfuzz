set -e
git clone-rev.sh https://github.com/trifectatechfoundation/libzstd-rs-sys "$PROJECT/repo" fe2c02929fb414c339eead1eccc6d56dc5f44d33
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-wasm-assert.patch"

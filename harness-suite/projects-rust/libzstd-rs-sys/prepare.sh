set -e
git clone-rev.sh https://github.com/trifectatechfoundation/libzstd-rs-sys "$PROJECT/repo" 3dc8c859efb1eb7264631c4781e1d811a5bcc8fb
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-wasm-assert.patch"

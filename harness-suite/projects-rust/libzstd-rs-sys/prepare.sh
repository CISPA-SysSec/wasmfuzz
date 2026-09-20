set -e
git clone-rev.sh https://github.com/trifectatechfoundation/libzstd-rs-sys "$PROJECT/repo" 621902bafdbbe6282f5d2dc8294ca4e2bc6f3bca
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-wasm-skip-c-oracle.patch"

set -e
git clone-rev.sh https://github.com/trifectatechfoundation/libzstd-rs-sys "$PROJECT/repo" 33e9a500570bcc384944814e383702baed0c7aec
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-wasm-skip-c-oracle.patch"

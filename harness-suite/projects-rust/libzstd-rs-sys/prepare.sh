set -e
git clone-rev.sh https://github.com/trifectatechfoundation/libzstd-rs-sys "$PROJECT/repo" 4e2dc77291dbc177cbe196318505d73b78952476
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-wasm-assert.patch"

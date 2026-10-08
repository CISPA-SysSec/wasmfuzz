set -e
git clone-rev.sh https://github.com/zip-rs/zip2.git "$PROJECT/repo" 8d5e026485ce51b0272a699b886ab13d03deaa08
git -C "$PROJECT/repo" apply "$PROJECT/port-fuzz-wasm-target.patch"

set -e
git clone-rev.sh https://github.com/zip-rs/zip2.git "$PROJECT/repo" 386788caafe7824397c90199006b7d0eaadec9ce
git -C "$PROJECT/repo" apply "$PROJECT/port-fuzz-wasm-target.patch"

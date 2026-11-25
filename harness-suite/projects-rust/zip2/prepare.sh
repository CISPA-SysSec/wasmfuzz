set -e
git clone-rev.sh https://github.com/zip-rs/zip2.git "$PROJECT/repo" 29e6259d704faf3a7ce13372e24ee496f641cc9d
git -C "$PROJECT/repo" apply "$PROJECT/port-fuzz-wasm-target.patch"

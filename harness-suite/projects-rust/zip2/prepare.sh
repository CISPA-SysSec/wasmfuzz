set -e
git clone-rev.sh https://github.com/zip-rs/zip2.git "$PROJECT/repo" 0e0e74b5c8e013037855f901b500767e01fe3626
git -C "$PROJECT/repo" apply "$PROJECT/port-fuzz-wasm-target.patch"

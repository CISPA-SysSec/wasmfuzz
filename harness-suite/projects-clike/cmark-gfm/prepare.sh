set -e
git clone-rev.sh https://github.com/github/cmark-gfm "$PROJECT/repo" 587a12bb54d95ac37241377e6ddc93ea0e45439b
git -C "$PROJECT/repo" apply ../wasm.patch
# replace unmaintaned harness
# cp "$PROJECT/cmark-fuzz.c" "$PROJECT/repo/test/cmark-fuzz.c"

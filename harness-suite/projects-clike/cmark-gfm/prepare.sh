set -e
git clone-rev.sh https://github.com/github/cmark-gfm "$PROJECT/repo" 499789b49373bfa045d0e7547e5ee63444c77bca
git -C "$PROJECT/repo" apply ../wasm.patch
# replace unmaintaned harness
# cp "$PROJECT/cmark-fuzz.c" "$PROJECT/repo/test/cmark-fuzz.c"

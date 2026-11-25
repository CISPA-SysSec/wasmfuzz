set -e
git clone-rev.sh https://github.com/github/cmark-gfm "$PROJECT/repo" 7fe8904ee31fa24b772ae565c4908b1394850de6
git -C "$PROJECT/repo" apply ../port-cmake-fuzz-flags.patch
# replace unmaintaned harness
# cp "$PROJECT/cmark-fuzz.c" "$PROJECT/repo/test/cmark-fuzz.c"

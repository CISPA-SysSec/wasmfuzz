set -e
# upstream HEAD; Chromium vendors sfv 0.15.0 (third_party/rust/sfv/v0_15), Firefox 0.14.
git clone-rev.sh https://github.com/undef1nd/sfv "$PROJECT/repo" b58a0d401837644f8e22624301c3955c08f78f1e
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-reparse-harnesses.patch"

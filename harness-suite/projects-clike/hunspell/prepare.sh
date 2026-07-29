set -e
git clone-rev.sh https://github.com/hunspell/hunspell.git "$PROJECT/repo" e6ae1729ad49059ebe328b68f69939e85e5b2d59
git -C "$PROJECT/repo" apply ../stub_clock.patch
git -C "$PROJECT/repo" apply ../fix_harness.patch

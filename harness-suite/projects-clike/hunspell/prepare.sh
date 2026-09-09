set -e
git clone-rev.sh https://github.com/hunspell/hunspell.git "$PROJECT/repo" e184e22c51fe213f4490e9b36998f0ad3e5e606b
git -C "$PROJECT/repo" apply ../stub_clock.patch
git -C "$PROJECT/repo" apply ../fix_harness.patch

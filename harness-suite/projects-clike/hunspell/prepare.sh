set -e
git clone-rev.sh https://github.com/hunspell/hunspell.git "$PROJECT/repo" 8fe07304cba052506915a405e915f6fc0c49aa94
git -C "$PROJECT/repo" apply ../stub_clock.patch
git -C "$PROJECT/repo" apply ../fix_harness.patch

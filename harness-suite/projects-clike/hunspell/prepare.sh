set -e
git clone-rev.sh https://github.com/hunspell/hunspell.git "$PROJECT/repo" ecc6dbb52025bdf3a766429988e64190d912765f
git -C "$PROJECT/repo" apply ../stub_clock.patch
git -C "$PROJECT/repo" apply ../fix_harness.patch

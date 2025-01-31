set -e
git clone-rev.sh https://github.com/hunspell/hunspell.git "$PROJECT/repo" 874abbbe65e228df525023afe176b42df34a7a4f
git -C "$PROJECT/repo" apply ../stub_clock.patch
git -C "$PROJECT/repo" apply ../fix_harness.patch

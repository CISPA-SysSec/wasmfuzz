set -e
git clone-rev.sh https://github.com/hunspell/hunspell.git "$PROJECT/repo" e994dceb97fb695bca6bfe5ad5665525426bf01f
git -C "$PROJECT/repo" apply ../stub_clock.patch
git -C "$PROJECT/repo" apply ../fix_harness.patch

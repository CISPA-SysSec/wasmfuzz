set -e
git clone-rev.sh https://github.com/hunspell/hunspell.git "$PROJECT/repo" b87a9c58a0868e5eada9b8f0eff4577ccee46cc7
git -C "$PROJECT/repo" apply ../port-stub-clock.patch
git -C "$PROJECT/repo" apply ../limit-hunzip-bufsize.patch

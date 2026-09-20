set -e
git clone-rev.sh https://github.com/hunspell/hunspell.git "$PROJECT/repo" a54018eda6e809128f74b7b1e660697d2fa824ca
git -C "$PROJECT/repo" apply ../port-stub-clock.patch
git -C "$PROJECT/repo" apply ../limit-hunzip-bufsize.patch

set -e
git clone-rev.sh https://github.com/hunspell/hunspell.git "$PROJECT/repo" b3428d0e1839b3d2cf38a8f057a930decc7344a4
git -C "$PROJECT/repo" apply ../port-stub-clock.patch
git -C "$PROJECT/repo" apply ../limit-hunzip-bufsize.patch

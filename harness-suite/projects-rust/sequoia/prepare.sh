set -e
git clone-rev.sh https://gitlab.com/sequoia-pgp/sequoia.git "$PROJECT/repo" daf94cf31eb7b9fbc4f89753f0b2eeddda650b4e
git -C "$PROJECT/repo" apply "$PROJECT/0001-fixes.patch"

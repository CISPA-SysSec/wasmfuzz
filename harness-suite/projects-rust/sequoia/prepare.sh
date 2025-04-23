set -e
git clone-rev.sh https://gitlab.com/sequoia-pgp/sequoia.git "$PROJECT/repo" e7d91ba4d78bf39b4152c553c8038894a92e079f
git -C "$PROJECT/repo" apply "$PROJECT/0001-fixes.patch"

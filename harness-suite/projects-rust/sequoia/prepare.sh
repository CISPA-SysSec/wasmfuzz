set -e
git clone-rev.sh https://gitlab.com/sequoia-pgp/sequoia.git "$PROJECT/repo" 05e6707ad2c68fa52a30c3c9a21d54dc00089919
git -C "$PROJECT/repo" apply "$PROJECT/0001-fixes.patch"

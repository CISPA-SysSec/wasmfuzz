set -e
git clone-rev.sh https://gitlab.com/sequoia-pgp/sequoia.git "$PROJECT/repo" ae4d9e69a292ee05cd34789cef734d155131130a
git -C "$PROJECT/repo" apply "$PROJECT/0001-fixes.patch"

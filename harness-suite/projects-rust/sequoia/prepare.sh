set -e
git clone-rev.sh https://gitlab.com/sequoia-pgp/sequoia.git "$PROJECT/repo" b329a8cc7de1ef7813d3cbf16746c248c62e9217
git -C "$PROJECT/repo" apply "$PROJECT/0001-fixes.patch"

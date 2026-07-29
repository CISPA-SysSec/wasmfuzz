set -e
git clone-rev.sh https://gitlab.com/sequoia-pgp/sequoia.git "$PROJECT/repo" d0aa59e33ad62af6f12b8b87d87ebefc7a554b6c
git -C "$PROJECT/repo" apply "$PROJECT/0001-fixes.patch"

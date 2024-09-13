set -e
git clone-rev.sh https://gitlab.com/sequoia-pgp/sequoia.git "$PROJECT/repo" 19ac82a17d143f376a987d979dd3b6cfd3a5a683
git -C "$PROJECT/repo" apply "$PROJECT/0001-fixes.patch"

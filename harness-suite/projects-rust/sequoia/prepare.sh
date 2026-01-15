set -e
git clone-rev.sh https://gitlab.com/sequoia-pgp/sequoia.git "$PROJECT/repo" 46b1ccdf72edb4eddcd7e73e33f71cf6fd9901dc
git -C "$PROJECT/repo" apply "$PROJECT/0001-fixes.patch"

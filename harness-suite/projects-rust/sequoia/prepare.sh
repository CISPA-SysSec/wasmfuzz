set -e
git clone-rev.sh https://gitlab.com/sequoia-pgp/sequoia.git "$PROJECT/repo" c948071849fe2b3baf590435eaaaf09fbef138be
git -C "$PROJECT/repo" apply "$PROJECT/0001-fixes.patch"

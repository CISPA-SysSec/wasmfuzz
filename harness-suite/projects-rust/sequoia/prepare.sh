set -e
git clone-rev.sh https://gitlab.com/sequoia-pgp/sequoia.git "$PROJECT/repo" c01f9b871c71cd7c7da614e22b4f3e928a45c805
git -C "$PROJECT/repo" apply "$PROJECT/0001-fixes.patch"

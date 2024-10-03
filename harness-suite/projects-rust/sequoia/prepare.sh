set -e
git clone-rev.sh https://gitlab.com/sequoia-pgp/sequoia.git "$PROJECT/repo" da09e6f8bda9169c7047229b262e00fbfa691bf1
git -C "$PROJECT/repo" apply "$PROJECT/0001-fixes.patch"

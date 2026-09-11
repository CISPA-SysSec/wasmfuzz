set -e
git clone-rev.sh https://gitlab.com/sequoia-pgp/sequoia.git "$PROJECT/repo" dbdb91f373b116512557f064267460d8a4cee873
git -C "$PROJECT/repo" apply "$PROJECT/fix-parser-assert-hardening.patch"

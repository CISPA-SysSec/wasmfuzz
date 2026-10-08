set -e
git clone-rev.sh https://gitlab.com/sequoia-pgp/sequoia.git "$PROJECT/repo" f1cc3012406e68c678e53d108960c8d1ae99dbd2
git -C "$PROJECT/repo" apply "$PROJECT/fix-parser-assert-hardening.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-rawcert-body-len-overflow.patch"

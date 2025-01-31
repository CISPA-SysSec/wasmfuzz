set -e
git clone-rev.sh https://github.com/rusticata/x509-parser.git "$PROJECT/repo" ce50cdb38a742dbe85a9a2f5fd79ad4caf2bf42a
git -C "$PROJECT/repo" apply "$PROJECT/0001-fixes.patch"

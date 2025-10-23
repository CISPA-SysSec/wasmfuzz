set -e
git clone-rev.sh https://github.com/rusticata/x509-parser.git "$PROJECT/repo" b7dcc9397b596cf9fa3df65115c3f405f1748b2a
git -C "$PROJECT/repo" apply "$PROJECT/remove-stale-cratesio-patch.patch"

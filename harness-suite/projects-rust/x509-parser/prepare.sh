set -e
git clone-rev.sh https://github.com/rusticata/x509-parser.git "$PROJECT/repo" acdbf7d0c2e4fa0353c107076541d7bcd353cd19
git -C "$PROJECT/repo" apply "$PROJECT/remove-stale-cratesio-patch.patch"

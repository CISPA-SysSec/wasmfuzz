set -e
git clone-rev.sh https://github.com/rusticata/x509-parser.git "$PROJECT/repo" 7b919a821341246883b9f41724727b8c413079f0
git -C "$PROJECT/repo" apply "$PROJECT/0001-fixes.patch"

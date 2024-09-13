set -e
git clone-rev.sh https://github.com/rusticata/x509-parser.git "$PROJECT/repo" 10fcbcc1786dba99fb707e9d5aac63abae10dd30
git -C "$PROJECT/repo" apply "$PROJECT/0001-fixes.patch"

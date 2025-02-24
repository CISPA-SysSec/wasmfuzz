set -e
git clone-rev.sh https://github.com/m4b/goblin.git "$PROJECT/repo" ac1fabdd2100bae949607a320fe5d8087c1e784a
git -C "$PROJECT/repo" apply "$PROJECT/fix-32-bit-overflows.patch"

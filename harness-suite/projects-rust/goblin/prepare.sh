set -e
git clone-rev.sh https://github.com/m4b/goblin.git "$PROJECT/repo" dca2e753b2abb66a38f42bcb245cf7232049e69e
git -C "$PROJECT/repo" apply "$PROJECT/fix-32-bit-overflows.patch"

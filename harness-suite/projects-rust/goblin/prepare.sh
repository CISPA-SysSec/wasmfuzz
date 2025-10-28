set -e
git clone-rev.sh https://github.com/m4b/goblin.git "$PROJECT/repo" 75479d43b8bc929e0e03c7a1290dcba78734500c
git -C "$PROJECT/repo" apply "$PROJECT/fix-32-bit-overflows.patch"

set -e
git clone-rev.sh https://github.com/m4b/goblin.git "$PROJECT/repo" 6a19a59878fbb233a84c8442115473370bcbfe38
git -C "$PROJECT/repo" apply "$PROJECT/fix-32-bit-overflows.patch"

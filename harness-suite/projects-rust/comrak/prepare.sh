set -e
git clone-rev.sh https://github.com/kivikakk/comrak.git "$PROJECT/repo" 835e68ea438868fdd2ee8e53683b26cd73d5f67d
git -C "$PROJECT/repo" apply "$PROJECT/fix-cm-write_prefix.patch"

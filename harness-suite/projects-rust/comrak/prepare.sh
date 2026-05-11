set -e
git clone-rev.sh https://github.com/kivikakk/comrak.git "$PROJECT/repo" b2410190b170b68aeaefd4388c341d7f578b91e7
git -C "$PROJECT/repo" apply "$PROJECT/fix-cm-write_prefix.patch"

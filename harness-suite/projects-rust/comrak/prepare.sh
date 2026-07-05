set -e
git clone-rev.sh https://github.com/kivikakk/comrak.git "$PROJECT/repo" baafcb063427af6611be3e06eaf4fe9b2d28582a
git -C "$PROJECT/repo" apply "$PROJECT/fix-cm-write_prefix.patch"

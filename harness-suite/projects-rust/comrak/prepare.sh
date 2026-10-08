set -e
git clone-rev.sh https://github.com/kivikakk/comrak.git "$PROJECT/repo" a28e394fc26e8be2d36b8fc630f6329da7a13cc1
git -C "$PROJECT/repo" apply "$PROJECT/fix-cm-write-prefix.patch"

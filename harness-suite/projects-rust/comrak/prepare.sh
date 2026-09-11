set -e
git clone-rev.sh https://github.com/kivikakk/comrak.git "$PROJECT/repo" 6fbe87fafde3953a9f3bc582804318593d703805
git -C "$PROJECT/repo" apply "$PROJECT/fix-cm-write-prefix.patch"

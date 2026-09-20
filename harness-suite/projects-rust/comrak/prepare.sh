set -e
git clone-rev.sh https://github.com/kivikakk/comrak.git "$PROJECT/repo" cf8955abe961454dff39cfb64952e1933645d870
git -C "$PROJECT/repo" apply "$PROJECT/fix-cm-write-prefix.patch"

set -e
git clone-rev.sh https://github.com/googlefonts/fontations "$PROJECT/repo" d91a0b4daa16889d11e3f7d46b9fef00a787eacf
git -C "$PROJECT/repo" apply "$PROJECT/fix-fvar-oob.patch"
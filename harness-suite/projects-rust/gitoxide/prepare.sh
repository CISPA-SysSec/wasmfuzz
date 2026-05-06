set -e
git clone-rev.sh https://github.com/Byron/gitoxide.git "$PROJECT/repo" 8af2691270a72c711bbec8100ce07273de29f52a
git -C "$PROJECT/repo" apply "$PROJECT/disable-incompatible.patch"

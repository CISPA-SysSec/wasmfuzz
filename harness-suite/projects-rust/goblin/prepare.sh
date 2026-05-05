set -e
git clone-rev.sh https://github.com/m4b/goblin.git "$PROJECT/repo" 41932a56a5d44e03a457e80cef8045276a588c70
git -C "$PROJECT/repo" apply "$PROJECT/fix-32-bit-overflows.patch"

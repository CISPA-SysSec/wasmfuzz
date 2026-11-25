set -e
git clone-rev.sh https://github.com/m4b/goblin.git "$PROJECT/repo" cc6beec889d74680d8f77626f508cb9d949dfc23
git -C "$PROJECT/repo" apply "$PROJECT/fix-32-bit-overflows.patch"

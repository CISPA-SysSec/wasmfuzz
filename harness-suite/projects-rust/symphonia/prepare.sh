set -e
git clone-rev.sh https://github.com/pdeljanov/symphonia.git "$PROJECT/repo" 505458eb1e479d84df0a65f95ab3d536d6350d29
git -C "$PROJECT/repo" apply "$PROJECT/fix-step-by.patch"

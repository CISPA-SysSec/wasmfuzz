set -e
git clone-rev.sh https://github.com/m4b/goblin.git "$PROJECT/repo" e370f7944ff6f2f3ec2488e523f5270b7cbe2bfb
git -C "$PROJECT/repo" apply "$PROJECT/fix-32-bit-overflows.patch"

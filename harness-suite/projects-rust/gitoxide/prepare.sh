set -e
git clone-rev.sh https://github.com/Byron/gitoxide.git "$PROJECT/repo" 5ffccd2f08d70576347e3ae17a66ca5a60f1d81c
git -C "$PROJECT/repo" apply "$PROJECT/disable-incompatible.patch"
# git -C "$PROJECT/repo" apply "$PROJECT/fix-workspace-lints.patch"

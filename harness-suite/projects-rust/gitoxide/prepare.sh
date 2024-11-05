set -e
git clone-rev.sh https://github.com/Byron/gitoxide.git "$PROJECT/repo" c081114ff885ca07032cad994970ed027a62a0cf
git -C "$PROJECT/repo" apply "$PROJECT/disable-incompatible.patch"
# git -C "$PROJECT/repo" apply "$PROJECT/fix-workspace-lints.patch"

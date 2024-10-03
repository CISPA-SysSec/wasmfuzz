set -e
git clone-rev.sh https://github.com/ordian/toml_edit.git "$PROJECT/repo" b05e8c489be8ebfc0acacc1ec3556d95cd8d2198
git -C "$PROJECT/repo" apply "$PROJECT/remove-harness-from-workspace.patch"

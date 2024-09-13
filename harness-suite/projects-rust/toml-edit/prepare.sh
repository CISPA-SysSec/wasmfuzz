set -e
git clone-rev.sh https://github.com/ordian/toml_edit.git "$PROJECT/repo" 1bfb7d7d79880289fc1f10ef3f6dd0b2b3267c17
git -C "$PROJECT/repo" apply "$PROJECT/remove-harness-from-workspace.patch"

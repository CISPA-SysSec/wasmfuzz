set -e
git clone-rev.sh https://github.com/ordian/toml_edit.git "$PROJECT/repo" 28e1063990dac5cfb86166c654885b65f7aaf5e8
git -C "$PROJECT/repo" apply "$PROJECT/remove-harness-from-workspace.patch"

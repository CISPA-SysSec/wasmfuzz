set -e
git clone-rev.sh https://github.com/ordian/toml_edit.git "$PROJECT/repo" 2923f5961d2ca977ced51fd784b6c8d64f01ee18
git -C "$PROJECT/repo" apply "$PROJECT/remove-harness-from-workspace.patch"

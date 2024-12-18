set -e
git clone-rev.sh https://github.com/ordian/toml_edit.git "$PROJECT/repo" f285793cf97bcd4b1f571be42d6c3b4a101aac63
git -C "$PROJECT/repo" apply "$PROJECT/remove-harness-from-workspace.patch"

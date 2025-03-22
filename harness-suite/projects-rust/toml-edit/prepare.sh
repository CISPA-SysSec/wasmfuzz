set -e
git clone-rev.sh https://github.com/ordian/toml_edit.git "$PROJECT/repo" 2298715850a24fe5e33571d4cc7b5fc9a04037e5
git -C "$PROJECT/repo" apply "$PROJECT/remove-harness-from-workspace.patch"

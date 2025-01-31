set -e
git clone-rev.sh https://github.com/ordian/toml_edit.git "$PROJECT/repo" f550dbfd7dd2bb50c65033f7d0620271151c1734
git -C "$PROJECT/repo" apply "$PROJECT/remove-harness-from-workspace.patch"

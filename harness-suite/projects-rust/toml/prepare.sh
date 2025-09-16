set -e
git clone-rev.sh https://github.com/toml-rs/toml "$PROJECT/repo" 9154dcb3b2eea8a84db183806411adf081bc0977
git -C "$PROJECT/repo" apply "$PROJECT/remove-harness-from-workspace.patch"

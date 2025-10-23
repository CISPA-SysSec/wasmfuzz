set -e
git clone-rev.sh https://github.com/toml-rs/toml "$PROJECT/repo" 80217f85ee8e6d91b4ed2469aecfdf93cef15985
git -C "$PROJECT/repo" apply "$PROJECT/remove-harness-from-workspace.patch"

set -e
git clone-rev.sh https://github.com/rust-lang/rustc-demangle.git "$PROJECT/repo" ca5202ef83ebe8cac06fc9048adbe939c7364ae6
git -C "$PROJECT/repo" apply "$PROJECT/remove-harness-from-workspace.patch"
git -C "$PROJECT/repo" apply "$PROJECT/native-c-sync-with-rust-v0.patch"

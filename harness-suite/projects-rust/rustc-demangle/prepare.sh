set -e
git clone-rev.sh https://github.com/rust-lang/rustc-demangle.git "$PROJECT/repo" f36e2988643d7db47a6aa6e328cc7ffd61343651
git -C "$PROJECT/repo" apply "$PROJECT/remove-harness-from-workspace.patch"
git -C "$PROJECT/repo" apply "$PROJECT/native-c-sync-with-rust-v0.patch"

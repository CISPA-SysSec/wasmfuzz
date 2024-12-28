set -e
git clone-rev.sh https://github.com/rust-lang/rustc-demangle.git "$PROJECT/repo" 6cbe55cb044e96d4f3644d6745060f3eb19c5db0
git -C "$PROJECT/repo" apply "$PROJECT/remove-harness-from-workspace.patch"

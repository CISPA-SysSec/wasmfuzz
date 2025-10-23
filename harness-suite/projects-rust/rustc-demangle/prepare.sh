set -e
git clone-rev.sh https://github.com/rust-lang/rustc-demangle.git "$PROJECT/repo" c5688cfec32d2bd00701836f12beb3560ee015b8
git -C "$PROJECT/repo" apply "$PROJECT/remove-harness-from-workspace.patch"

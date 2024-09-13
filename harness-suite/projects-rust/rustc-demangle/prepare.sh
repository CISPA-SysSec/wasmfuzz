set -e
git clone-rev.sh https://github.com/rust-lang/rustc-demangle.git "$PROJECT/repo" f053741061bd1686873a467a7d9ef22d2f1fb876
git -C "$PROJECT/repo" apply "$PROJECT/remove-harness-from-workspace.patch"

set -e
git clone-rev.sh https://github.com/rust-lang/rustc-demangle.git "$PROJECT/repo" 83f1bbd6793a2dbd5fa94b185a0cd9bb98d8332f
git -C "$PROJECT/repo" apply "$PROJECT/remove-harness-from-workspace.patch"

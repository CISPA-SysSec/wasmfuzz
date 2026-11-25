set -e
git clone-rev.sh https://github.com/rust-lang/rustc-demangle.git "$PROJECT/repo" 4023665a9bafb7cd9808033fd76fa50f83b9542c
git -C "$PROJECT/repo" apply "$PROJECT/port-remove-harness-from-workspace.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-native-c-sync-with-rust-v0.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-native-c-dyn-assoc-const-binding.patch"

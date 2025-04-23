set -e
git clone-rev.sh https://github.com/rust-lang/rust-analyzer.git "$PROJECT/repo" 1748a848885640be205c6dfdb72e1f1942049518
git -C "$PROJECT/repo" apply "$PROJECT/fix.patch"

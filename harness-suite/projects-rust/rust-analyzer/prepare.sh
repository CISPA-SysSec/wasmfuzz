set -e
git clone-rev.sh https://github.com/rust-lang/rust-analyzer.git "$PROJECT/repo" fe5a925a74efde7ec6a7d3e388b946f96d36e760
git -C "$PROJECT/repo" apply "$PROJECT/fix.patch"

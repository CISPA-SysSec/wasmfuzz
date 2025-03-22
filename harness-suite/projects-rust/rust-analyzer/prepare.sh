set -e
git clone-rev.sh https://github.com/rust-lang/rust-analyzer.git "$PROJECT/repo" 1c72e5403b016513cead49b7b65dc0a96b252dcd
git -C "$PROJECT/repo" apply "$PROJECT/fix.patch"

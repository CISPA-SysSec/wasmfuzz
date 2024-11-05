set -e
git clone-rev.sh https://github.com/rust-lang/rust-analyzer.git "$PROJECT/repo" 8dd53a3a46adffdc7928bbfabab90d6348c9a089
git -C "$PROJECT/repo" apply "$PROJECT/fix.patch"

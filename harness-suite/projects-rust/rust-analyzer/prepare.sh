set -e
git clone-rev.sh https://github.com/rust-lang/rust-analyzer.git "$PROJECT/repo" e1a76671af2fbc74c84c18ba18fcda5e653d7531
git -C "$PROJECT/repo" apply "$PROJECT/fix.patch"

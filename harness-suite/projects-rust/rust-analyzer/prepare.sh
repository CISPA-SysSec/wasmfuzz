set -e
git clone-rev.sh https://github.com/rust-lang/rust-analyzer.git "$PROJECT/repo" f5e7172e96ff8a75af99ac570085d22a4afab09b
git -C "$PROJECT/repo" apply "$PROJECT/fix.patch"

set -e
git clone-rev.sh https://github.com/rust-lang/rust-analyzer.git "$PROJECT/repo" 9fd70519507b673fae250f84b0990e7e8155ca98
git -C "$PROJECT/repo" apply "$PROJECT/fix.patch"

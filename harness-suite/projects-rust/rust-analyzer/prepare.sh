set -e
git clone-rev.sh https://github.com/rust-lang/rust-analyzer.git "$PROJECT/repo" bd06def3d3acd5f54fac953a015c0ac9b1e71b2f
git -C "$PROJECT/repo" apply "$PROJECT/fix.patch"

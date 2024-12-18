set -e
git clone-rev.sh https://github.com/libexpat/libexpat "$PROJECT/repo" 8cb7d5677286f7bf4d606c1e0eb16f29ca4c50c9
git -C "$PROJECT/repo" apply ../fix_link_args.patch

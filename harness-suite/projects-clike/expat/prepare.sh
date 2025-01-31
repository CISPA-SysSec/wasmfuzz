set -e
git clone-rev.sh https://github.com/libexpat/libexpat "$PROJECT/repo" 1ddd2ef11d3a6aa8f33ea6ebba44cfe3e67eccbb
git -C "$PROJECT/repo" apply ../fix_link_args.patch

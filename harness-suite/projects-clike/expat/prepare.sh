set -e
git clone-rev.sh https://github.com/libexpat/libexpat "$PROJECT/repo" 493406dbcc915c8209514241297fd2734a9e3a9b
git -C "$PROJECT/repo" apply ../fix_link_args.patch

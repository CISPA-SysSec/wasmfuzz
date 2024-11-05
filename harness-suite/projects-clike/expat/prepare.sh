set -e
git clone-rev.sh https://github.com/libexpat/libexpat "$PROJECT/repo" 0467264ccadade72a9e4fedecfc6566998e718ed
git -C "$PROJECT/repo" apply ../fix_link_args.patch

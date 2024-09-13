set -e
git clone-rev.sh https://github.com/libexpat/libexpat "$PROJECT/repo" ed4090af841ebd8a7b2e367280407d74e748a7dd
git -C "$PROJECT/repo" apply ../fix_link_args.patch

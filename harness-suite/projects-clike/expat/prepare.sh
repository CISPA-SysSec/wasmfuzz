set -e
git clone-rev.sh https://github.com/libexpat/libexpat "$PROJECT/repo" 8f8d48265eb2d05ef60c606b781d53118357ef86
git -C "$PROJECT/repo" apply ../fix_link_args.patch

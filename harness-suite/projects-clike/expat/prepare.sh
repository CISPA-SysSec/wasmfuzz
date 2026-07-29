set -e
git clone-rev.sh https://github.com/libexpat/libexpat "$PROJECT/repo" 7d93af0965eee44fde42d9e9ec8761ae2894e8e8
git -C "$PROJECT/repo" apply ../fix_link_args.patch
git -C "$PROJECT/repo" apply ../disable-lpm-harness.patch

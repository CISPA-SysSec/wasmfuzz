set -e
git clone-rev.sh https://github.com/libexpat/libexpat "$PROJECT/repo" 8d3a86bf328365c1f30506adb6919221814a9915
git -C "$PROJECT/repo" apply ../fix_link_args.patch
git -C "$PROJECT/repo" apply ../disable-lpm-harness.patch

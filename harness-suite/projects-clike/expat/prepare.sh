set -e
git clone-rev.sh https://github.com/libexpat/libexpat "$PROJECT/repo" 40f97d787185b63c1c761a53308f2ab2883308ee
git -C "$PROJECT/repo" apply ../port-fuzz-link-args.patch
git -C "$PROJECT/repo" apply ../port-disable-lpm-harness.patch

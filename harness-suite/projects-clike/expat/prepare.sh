set -e
git clone-rev.sh https://github.com/libexpat/libexpat "$PROJECT/repo" ff6e1d7e750bbe245178f51a47a965dc8342861a
git -C "$PROJECT/repo" apply ../port-fuzz-link-args.patch
git -C "$PROJECT/repo" apply ../port-disable-lpm-harness.patch

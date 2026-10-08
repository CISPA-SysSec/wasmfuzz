set -e
git clone-rev.sh https://github.com/libexpat/libexpat "$PROJECT/repo" b329498d61e41227835cf53544e931422de07b87
git -C "$PROJECT/repo" apply ../port-fuzz-link-args.patch
git -C "$PROJECT/repo" apply ../port-disable-lpm-harness.patch

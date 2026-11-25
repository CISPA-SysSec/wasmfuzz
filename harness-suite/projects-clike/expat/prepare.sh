set -e
git clone-rev.sh https://github.com/libexpat/libexpat "$PROJECT/repo" bbdb35e85b68284cb20ad8876c56e9b80175babb
git -C "$PROJECT/repo" apply ../port-fuzz-link-args.patch
git -C "$PROJECT/repo" apply ../port-disable-lpm-harness.patch
# hash a bounded window of the input for the hash salt (constant cost, perf)
git -C "$PROJECT/repo" apply ../fuzz-bounded-salt-hash.patch

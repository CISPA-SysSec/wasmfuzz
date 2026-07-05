set -e
git clone-rev.sh https://github.com/libexpat/libexpat "$PROJECT/repo" 11cd58eb92dd8ebd85e018eabb7357ee28fec1c7
git -C "$PROJECT/repo" apply ../fix_link_args.patch
git -C "$PROJECT/repo" apply ../disable-lpm-harness.patch

set -e
git clone-rev.sh https://github.com/libexpat/libexpat "$PROJECT/repo" 6fd58ad63093eb05a1cda8477f776007fb8227f7
git -C "$PROJECT/repo" apply ../fix_link_args.patch
git -C "$PROJECT/repo" apply ../disable-lpm-harness.patch

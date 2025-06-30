set -e
git clone-rev.sh https://github.com/libexpat/libexpat "$PROJECT/repo" 837347369fc30ee33fe66fd166ba28a99843b3a8
git -C "$PROJECT/repo" apply ../fix_link_args.patch
git -C "$PROJECT/repo" apply ../disable-lpm-harness.patch

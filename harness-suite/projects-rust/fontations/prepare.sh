set -e
git clone-rev.sh https://github.com/googlefonts/fontations "$PROJECT/repo" 4f115482ebf24d1989e2c4446bf877d4812a268b
git -C "$PROJECT/repo" apply "$PROJECT/fix-varc-region-count-alloc.patch"

set -e
git clone-rev.sh https://github.com/pdeljanov/symphonia.git "$PROJECT/repo" 706fc0fcf1d87183921481345c00e494894f61c6
git -C "$PROJECT/repo" apply "$PROJECT/fix.patch"

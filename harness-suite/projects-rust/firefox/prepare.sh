set -e
git clone-rev.sh https://github.com/mozilla-firefox/firefox "$PROJECT/repo" bbdd22a8b58a05e5b269fe341b02ce11426c550f
git -C "$PROJECT/repo" apply "$PROJECT/fix-lut-interp-linear-float.patch"

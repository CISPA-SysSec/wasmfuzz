set -e
git clone-rev.sh https://github.com/mozilla-firefox/firefox "$PROJECT/repo" 1f3fe59d5fab396251459c20e4bb16a8761f280c
git -C "$PROJECT/repo" apply "$PROJECT/fix-lut-interp-linear-float.patch"

set -e
git clone-rev.sh https://github.com/mozilla-firefox/firefox "$PROJECT/repo" 870d8e9d5932e8324320c71a773a2ca43c9fd5a3 --sparse=/gfx/qcms/,/testing/mozbase/rust/
git -C "$PROJECT/repo" apply "$PROJECT/fix-lut-interp-linear-float.patch"

set -e
git clone-rev.sh https://github.com/mozilla-firefox/firefox "$PROJECT/repo" 4ad2eb15b14e85132e844ef6d46c1ece5b3b9299 --sparse=/gfx/qcms/,/testing/mozbase/rust/
git -C "$PROJECT/repo" apply "$PROJECT/fix-lut-interp-linear-float.patch"

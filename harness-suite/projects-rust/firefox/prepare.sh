set -e
git clone-rev.sh https://github.com/mozilla-firefox/firefox "$PROJECT/repo" 2072eb612d1838fbad4a29d26d78c976f091f31d --sparse=/gfx/qcms/,/testing/mozbase/rust/
git -C "$PROJECT/repo" apply "$PROJECT/fix-lut-interp-linear-float.patch"

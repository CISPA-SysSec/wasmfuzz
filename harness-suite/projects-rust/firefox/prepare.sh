set -e
git clone-rev.sh https://github.com/mozilla-firefox/firefox "$PROJECT/repo" 023cb8315420edf23536fc0fde97d5717e72f5b1
git -C "$PROJECT/repo" apply "$PROJECT/fix-lut-interp-linear-float.patch"

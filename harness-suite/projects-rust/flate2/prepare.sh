set -e
# upstream HEAD; Chromium vendors flate2 1.1.10, Firefox 1.1.4.
git clone-rev.sh https://github.com/rust-lang/flate2-rs "$PROJECT/repo" 94d6150fb896472d176618db50230571082ac7f3
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-decode-harnesses.patch"

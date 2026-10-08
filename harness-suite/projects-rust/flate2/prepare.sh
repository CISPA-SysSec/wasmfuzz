set -e
# upstream HEAD; Chromium vendors flate2 1.1.10, Firefox 1.1.4.
git clone-rev.sh https://github.com/rust-lang/flate2-rs "$PROJECT/repo" fcc804306677bf8cfde2250bf0472d61b75d1c45
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-decode-harnesses.patch"

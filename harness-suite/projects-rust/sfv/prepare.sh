set -e
# upstream HEAD; Chromium vendors sfv 0.15.0 (third_party/rust/sfv/v0_15), Firefox 0.14.
git clone-rev.sh https://github.com/undef1nd/sfv "$PROJECT/repo" da069d4457a14f70418e581e30b293d63492b777
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-reparse-harnesses.patch"

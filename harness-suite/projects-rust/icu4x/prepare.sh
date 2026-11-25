set -e
git clone-rev.sh https://github.com/unicode-org/icu4x "$PROJECT/repo" 62676f3b987ccaf3a9273a36a7c2e07183b2d8e9
# The harness crate in $PROJECT/fuzz depends on the ICU4X crates in $PROJECT/repo by path.
# normalizer_compare_self and calendar_{construction,add,until} are copied from upstream
# (components/{normalizer,calendar}/fuzz); the remaining harnesses are new. Drop the
# upstream fuzz crates so build-rust-harness.py only builds $PROJECT/fuzz.
rm -rf "$PROJECT"/repo/components/*/fuzz

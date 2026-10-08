set -e
git clone-rev.sh https://github.com/unicode-org/icu4x "$PROJECT/repo" 499002b68a169585eeb3ba13608abad66f6d3720
# The harness crate in $PROJECT/fuzz depends on the ICU4X crates in $PROJECT/repo by path.
# normalizer_compare_self and calendar_{construction,add,until} are copied from upstream
# (components/{normalizer,calendar}/fuzz); the remaining harnesses are new. Drop the
# upstream fuzz crates so build-rust-harness.py only builds $PROJECT/fuzz.
rm -rf "$PROJECT"/repo/components/*/fuzz

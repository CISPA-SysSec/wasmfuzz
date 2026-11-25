set -e
git clone-rev.sh https://github.com/google/json5format.git "$PROJECT/repo" 25a594b7daacb4605241dc8d63e7c36411208c87
# fuzz_parse compiled the parser regexes (lazy_static) during the first input.
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-parse-init-regexes.patch"

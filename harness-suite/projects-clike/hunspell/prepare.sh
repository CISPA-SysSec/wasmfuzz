set -e
git clone-rev.sh https://github.com/hunspell/hunspell.git "$PROJECT/repo" c83e53fc456a14ff9bb0c572f7d688e88b346b75
git -C "$PROJECT/repo" apply ../stub_clock.patch
git -C "$PROJECT/repo" apply ../fix_harness.patch

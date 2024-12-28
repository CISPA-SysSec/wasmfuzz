set -e
git clone-rev.sh https://github.com/hunspell/hunspell.git "$PROJECT/repo" 3e7db93359347a23b547096d43874d8cc017dfa5
git -C "$PROJECT/repo" apply ../stub_clock.patch
git -C "$PROJECT/repo" apply ../fix_harness.patch

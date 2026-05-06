set -e
git clone-rev.sh https://github.com/hunspell/hunspell.git "$PROJECT/repo" 3522bd6eacf06df256bcc49c28c4511965cf204d
git -C "$PROJECT/repo" apply ../stub_clock.patch
git -C "$PROJECT/repo" apply ../fix_harness.patch

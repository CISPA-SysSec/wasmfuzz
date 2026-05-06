set -e
git clone-rev.sh https://github.com/openthread/openthread "$PROJECT/repo" bdea2ae98c489c455b43cdbc9dfa0b473629880c --recursive
git -C "$PROJECT/repo" apply ../wasm-tcplp.patch
git -C "$PROJECT/repo" apply ../fix-harness-include.patch
git -C "$PROJECT/repo" apply ../disable-nexus-tests.patch

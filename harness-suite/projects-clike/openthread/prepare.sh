set -e
git clone-rev.sh https://github.com/openthread/openthread "$PROJECT/repo" 9cc2cb3e96b8282fdc31725bcb397eceb7f4a53a --recursive
git -C "$PROJECT/repo" apply ../wasm-tcplp.patch
git -C "$PROJECT/repo" apply ../fix-harness-include.patch

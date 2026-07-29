set -e
git clone-rev.sh https://github.com/openthread/openthread "$PROJECT/repo" 54dce1c674d2f3363d880f1558f8781cfc8e2a6e --recursive
git -C "$PROJECT/repo" apply ../wasm-tcplp.patch
git -C "$PROJECT/repo" apply ../fix-harness-include.patch

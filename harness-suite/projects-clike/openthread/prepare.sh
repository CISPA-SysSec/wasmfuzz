set -e
git clone-rev.sh https://github.com/openthread/openthread "$PROJECT/repo" f34c5e5476829d9205e80b37fccc2bdfe97e1dab --recursive
git -C "$PROJECT/repo" apply ../wasm-tcplp.patch
git -C "$PROJECT/repo" apply ../fix-harness-include.patch

set -e
git clone-rev.sh https://github.com/openthread/openthread "$PROJECT/repo" c6f3f1ff314d517ee7deeb03cdfde9701106ff55
git -C "$PROJECT/repo" apply ../wasm-tcplp.patch
git -C "$PROJECT/repo" apply ../fix-harness-include.patch

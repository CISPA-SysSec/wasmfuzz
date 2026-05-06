set -e
git clone-rev.sh https://github.com/openthread/openthread "$PROJECT/repo" ef6fabd7580ff1e24bc3c82bf070fe18a19dcaeb --recursive
git -C "$PROJECT/repo" apply ../wasm-tcplp.patch
git -C "$PROJECT/repo" apply ../fix-harness-include.patch
git -C "$PROJECT/repo" apply ../disable-nexus-tests.patch

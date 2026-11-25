set -e
git clone-rev.sh https://github.com/openthread/openthread "$PROJECT/repo" 938d74cf766a4bbe88ec73155ebd508caf270b23 --recursive
git -C "$PROJECT/repo" apply ../port-tcplp-ehostdown.patch
git -C "$PROJECT/repo" apply ../fix-fuzz-missing-assert-include.patch

set -e
git clone-rev.sh https://github.com/openthread/openthread "$PROJECT/repo" 22cc9c363224b0fa6fe4dcc9befe732aacae27d0 --recursive
git -C "$PROJECT/repo" apply ../port-tcplp-ehostdown.patch
git -C "$PROJECT/repo" apply ../fix-fuzz-missing-assert-include.patch

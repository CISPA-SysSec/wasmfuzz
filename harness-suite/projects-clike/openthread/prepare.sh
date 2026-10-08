set -e
git clone-rev.sh https://github.com/openthread/openthread "$PROJECT/repo" 0268dd07caba14009b8243e5523c868b93cb2c32 --recursive
git -C "$PROJECT/repo" apply ../port-tcplp-ehostdown.patch
git -C "$PROJECT/repo" apply ../fix-fuzz-missing-assert-include.patch

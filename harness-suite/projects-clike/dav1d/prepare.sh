set -e

git clone-rev.sh https://github.com/videolan/dav1d "$PROJECT/repo" 060854a5980c94526965124b9761b5c8bfae85df
git -C "$PROJECT/repo" apply ../fix-wasi.patch

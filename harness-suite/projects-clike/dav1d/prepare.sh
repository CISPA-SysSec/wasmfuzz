set -e

git clone-rev.sh https://github.com/videolan/dav1d "$PROJECT/repo" 54706fc6bc0cdecab7e9593974a4039cc038fca7
git -C "$PROJECT/repo" apply ../fix-wasi.patch

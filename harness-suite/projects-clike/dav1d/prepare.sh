set -e

git clone-rev.sh https://github.com/videolan/dav1d "$PROJECT/repo" c2e9c9e58ac91b75ed58ec5132eb9f35c8fbb40d
git -C "$PROJECT/repo" apply ../port-wasi-meson.patch

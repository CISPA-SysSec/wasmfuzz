set -e

git clone-rev.sh https://github.com/videolan/dav1d "$PROJECT/repo" bf5a8792744ee78c977dfb16503f9156dde6401d
git -C "$PROJECT/repo" apply ../port-wasi-meson.patch

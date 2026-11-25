set -e

git clone-rev.sh https://github.com/videolan/dav1d "$PROJECT/repo" 918e7a67461da56f9c7b5c20842ea1d81b613945
git -C "$PROJECT/repo" apply ../port-wasi-meson.patch
# dav1d_open() builds its static tables on the first call: do it at init, not in the first input.
git -C "$PROJECT/repo" apply ../fuzz-init-tables-once.patch

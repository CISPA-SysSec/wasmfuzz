set -e

git clone-rev.sh https://code.videolan.org/videolan/dav2d.git "$PROJECT/repo" 04c1036f228bb65339ce33856e945bf8783d442c
git -C "$PROJECT/repo" apply ../port-wasi-meson.patch
git -C "$PROJECT/repo" apply ../fix-cfl-mh-gen-y-non420.patch

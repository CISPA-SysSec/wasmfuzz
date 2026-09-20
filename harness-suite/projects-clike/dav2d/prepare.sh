set -e

git clone-rev.sh https://code.videolan.org/videolan/dav2d.git "$PROJECT/repo" 446187ca6a12ce82accd1025970a3e4e395643f5
git -C "$PROJECT/repo" apply ../port-wasi-meson.patch
git -C "$PROJECT/repo" apply ../fix-cfl-mh-gen-y-non420.patch

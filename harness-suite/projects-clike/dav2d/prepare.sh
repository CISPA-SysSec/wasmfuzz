set -e

git clone-rev.sh https://code.videolan.org/videolan/dav2d.git "$PROJECT/repo" d80982b2f7576385a0c5a148ce5f303a6b2809ef
git -C "$PROJECT/repo" apply ../port-wasi-meson.patch
git -C "$PROJECT/repo" apply ../fix-cfl-mh-gen-y-non420.patch

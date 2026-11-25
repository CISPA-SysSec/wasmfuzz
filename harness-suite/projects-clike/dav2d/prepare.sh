set -e

git clone-rev.sh https://code.videolan.org/videolan/dav2d.git "$PROJECT/repo" 74bfb0accd9891a90b85cda08fff2cd20e98b07b
git -C "$PROJECT/repo" apply ../port-wasi-meson.patch
git -C "$PROJECT/repo" apply ../fix-intrabc-dv-validity.patch
git -C "$PROJECT/repo" apply ../fix-tip-scaled-refine.patch
# dav2d_open() builds its static tables on the first call: do it at init, not in the first input.
git -C "$PROJECT/repo" apply ../fuzz-init-tables-once.patch

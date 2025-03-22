set -e

git clone-rev.sh https://github.com/pnggroup/libpng.git "$PROJECT/repo" 34005e3d3d373c0c36898cc55eae48a79c8238a1
git -C "$PROJECT/repo" apply ../hook_png_error.patch
git -C "$PROJECT/repo" apply ../libpng_read_fuzzer_disable_setjmp.patch

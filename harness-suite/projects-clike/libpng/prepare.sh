set -e

git clone-rev.sh https://github.com/pnggroup/libpng.git "$PROJECT/repo" 812c34c13c27a963073e546c720f5a7b88b1ed00
git -C "$PROJECT/repo" apply ../hook_png_error.patch
git -C "$PROJECT/repo" apply ../libpng_read_fuzzer_disable_setjmp.patch

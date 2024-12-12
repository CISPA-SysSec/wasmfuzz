set -e

git clone-rev.sh https://github.com/pnggroup/libpng.git "$PROJECT/repo" c1cc0f3f4c3d4abd11ca68c59446a29ff6f95003
git -C "$PROJECT/repo" apply ../hook_png_error.patch
git -C "$PROJECT/repo" apply ../libpng_read_fuzzer_disable_setjmp.patch

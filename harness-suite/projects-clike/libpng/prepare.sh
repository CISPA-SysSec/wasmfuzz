set -e

git clone-rev.sh https://github.com/glennrp/libpng.git "$PROJECT/repo" 76e5ec217fbdc882bacc40ae3f2276d28507c341
git -C "$PROJECT/repo" apply ../hook_png_error.patch
git -C "$PROJECT/repo" apply ../libpng_read_fuzzer_disable_setjmp.patch

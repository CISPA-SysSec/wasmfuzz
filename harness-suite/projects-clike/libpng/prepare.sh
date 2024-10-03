set -e

git clone-rev.sh https://github.com/glennrp/libpng.git "$PROJECT/repo" d3cf9b6e22fca25273e87d0b11882a7f886c97fe
git -C "$PROJECT/repo" apply ../hook_png_error.patch
git -C "$PROJECT/repo" apply ../libpng_read_fuzzer_disable_setjmp.patch

set -e

git clone-rev.sh https://github.com/glennrp/libpng.git "$PROJECT/repo" e4a31f024b6158aaaf55a43502f574d5f5d1c894
git -C "$PROJECT/repo" apply ../hook_png_error.patch
git -C "$PROJECT/repo" apply ../libpng_read_fuzzer_disable_setjmp.patch

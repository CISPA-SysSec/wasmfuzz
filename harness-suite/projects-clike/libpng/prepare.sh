set -e

git clone-rev.sh https://github.com/pnggroup/libpng.git "$PROJECT/repo" 640204280f8109d7165f95d2b177f89baf20b253
git clone-rev.sh https://github.com/madler/zlib.git "$PROJECT/zlib" 5a82f71ed1dfc0bec044d9702463dbdf84ea3b71

git -C "$PROJECT/repo" apply ../hook_png_error.patch
git -C "$PROJECT/repo" apply ../libpng_read_fuzzer_disable_setjmp.patch

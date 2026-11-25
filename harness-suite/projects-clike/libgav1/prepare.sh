set -e

# upstream HEAD; Chromium ships c1deec657b (third_party/libgav1/README.chromium); Firefox does not ship libgav1.
git clone-rev.sh https://chromium.googlesource.com/codecs/libgav1 "$PROJECT/repo" 9f78a5b81409f4880ec0c96cd422851aab9d6d74
git -C "$PROJECT/repo" apply ../port-wasi-fuzzer-temp-file.patch
git -C "$PROJECT/repo" apply ../port-wasi-single-thread.patch

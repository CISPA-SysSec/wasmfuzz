set -e

# upstream HEAD; Chromium ships c1deec657b (third_party/libgav1/README.chromium); Firefox does not ship libgav1.
git clone-rev.sh https://chromium.googlesource.com/codecs/libgav1 "$PROJECT/repo" c1deec657b32b911920c78e078cfd089faa77200
git -C "$PROJECT/repo" apply ../port-wasi-fuzzer-temp-file.patch
git -C "$PROJECT/repo" apply ../port-wasi-single-thread.patch

set -e

# upstream HEAD; Chromium ships 7b6197cb8f (third_party/libaom/README.chromium),
# Firefox de45b6e71c (media/libaom/moz.yaml).
git clone-rev.sh https://aomedia.googlesource.com/aom "$PROJECT/repo" 6181313122767d38752d938b565dec1c0abe1892

git -C "$PROJECT/repo" apply ../port-wasi-no-setjmp.patch
git -C "$PROJECT/repo" apply ../port-fuzzer-single-thread.patch

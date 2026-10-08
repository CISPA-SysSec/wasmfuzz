set -e

# upstream HEAD; Chromium ships 5e680f3080 (DEPS), Firefox d2413e2ca1 (media/libvpx/moz.yaml).
git clone-rev.sh https://chromium.googlesource.com/webm/libvpx "$PROJECT/repo" 5e680f30801d03c21078f8c4b772464752516211
git -C "$PROJECT/repo" apply ../port-wasi-setjmp-exit-testcase.patch

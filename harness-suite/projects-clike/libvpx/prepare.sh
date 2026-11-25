set -e

# upstream HEAD; Chromium ships 5e680f3080 (DEPS), Firefox d2413e2ca1 (media/libvpx/moz.yaml).
git clone-rev.sh https://chromium.googlesource.com/webm/libvpx "$PROJECT/repo" 0c7afa13cc76906a0895eb8661703373561b37c7
git -C "$PROJECT/repo" apply ../port-wasi-setjmp-exit-testcase.patch
git -C "$PROJECT/repo" apply ../fix-vp9-single-thread-without-multithread.patch

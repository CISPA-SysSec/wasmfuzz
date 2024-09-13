set -e
git clone-rev.sh https://github.com/RustAudio/lewton.git "$PROJECT/repo" bb2955b717094b40260902cf2f8dd9c5ea62a84a
git -C "$PROJECT/repo" apply "$PROJECT/0001-add-fuzzer.patch"
git -C "$PROJECT/repo" apply "$PROJECT/0002-avoid-allocator-panics-on-32-bit-targets.patch"

set -e
git clone-rev.sh https://github.com/RustAudio/lewton.git "$PROJECT/repo" bb2955b717094b40260902cf2f8dd9c5ea62a84a
git -C "$PROJECT/repo" apply "$PROJECT/0001-add-fuzzer.patch"
git -C "$PROJECT/repo" apply "$PROJECT/0002-avoid-allocator-panics-on-32-bit-targets.patch"
git -C "$PROJECT/repo" apply "$PROJECT/0003-vq-lookup-capacity-checked-mul.patch"
git -C "$PROJECT/repo" apply "$PROJECT/0005-audio-window-bounds.patch"
git -C "$PROJECT/repo" apply "$PROJECT/0006-alloc-cap-isize.patch"

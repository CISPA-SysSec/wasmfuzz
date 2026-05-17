set -e
git clone-rev.sh https://github.com/RustAudio/lewton.git "$PROJECT/repo" bb2955b717094b40260902cf2f8dd9c5ea62a84a
git -C "$PROJECT/repo" apply "$PROJECT/0001-add-fuzzer.patch"
git -C "$PROJECT/repo" apply "$PROJECT/0002-avoid-allocator-panics-on-32-bit-targets.patch"
git -C "$PROJECT/repo" apply "$PROJECT/0003-vq-lookup-capacity-checked-mul.patch"
git -C "$PROJECT/repo" apply "$PROJECT/0005-audio-window-bounds.patch"
git -C "$PROJECT/repo" apply "$PROJECT/0006-alloc-cap-isize.patch"
git -C "$PROJECT/repo" apply "$PROJECT/0007-fallible-codebook-multiplicands-allocation.patch"
git -C "$PROJECT/repo" apply "$PROJECT/0008-cap-vq-value-vectors.patch"
git -C "$PROJECT/repo" apply "$PROJECT/0009-floor0-cos-coeff-bounds.patch"
git -C "$PROJECT/repo" apply "$PROJECT/0010-floor0-codebook-index.patch"
git -C "$PROJECT/repo" apply "$PROJECT/0011-floor0-cos-coeff-loop-index.patch"
git -C "$PROJECT/repo" apply "$PROJECT/0012-residue-type2-deinterleave-bounds.patch"
git -C "$PROJECT/repo" apply "$PROJECT/0013-residue-no-vq-lookup-error.patch"

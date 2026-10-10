set -e
# NOTE: these are a dependent series - later patches edit lines earlier ones
#       introduce, so keep them in this order.
git clone-rev.sh https://github.com/RustAudio/lewton.git "$PROJECT/repo" bb2955b717094b40260902cf2f8dd9c5ea62a84a
git -C "$PROJECT/repo" apply "$PROJECT/port-add-fuzzer.patch"
git -C "$PROJECT/repo" apply "$PROJECT/limit-comment-header-allocs.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-vq-lookup-capacity-checked-mul.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-audio-window-bounds.patch"
git -C "$PROJECT/repo" apply "$PROJECT/limit-alloc-cap-isize.patch"
git -C "$PROJECT/repo" apply "$PROJECT/limit-fallible-codebook-multiplicands.patch"
git -C "$PROJECT/repo" apply "$PROJECT/limit-vq-value-vectors.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-floor0-cos-coeff-bounds.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-floor0-codebook-index.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-floor0-cos-coeff-loop-index.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-residue-type2-deinterleave-bounds.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-residue-no-vq-lookup-error.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-residue-zero-divisors.patch"

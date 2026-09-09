set -e
git clone-rev.sh https://github.com/libjxl/jxl-rs "$PROJECT/repo" 450fef016d5d9c848a92b041b29f844a008f1e78
git -C "$PROJECT/repo" apply "$PROJECT/disable-simd.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-decode-resource-limits.patch"
git -C "$PROJECT/repo" apply "$PROJECT/cap-untrusted-parse-dimensions.patch"
#
git -C "$PROJECT/repo" apply "$PROJECT/fix-squeeze-empty-inputs.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-blending-bounds.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-modular-pipeline-bounds.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-rct-grid-kind-mismatch.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-low-memory-pipeline-downsampling.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-entropy-restore-zero-rewind.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-extend-ref-frame-bounds.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-vardct-lf-rect-bounds.patch"

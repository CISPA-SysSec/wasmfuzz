set -e
git clone-rev.sh https://github.com/libjxl/jxl-rs "$PROJECT/repo" fce6e280777bc0d0c76ad2f58af9d0e26fe94d5a
git -C "$PROJECT/repo" apply "$PROJECT/port-disable-simd.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-decode-resource-limits.patch"
git -C "$PROJECT/repo" apply "$PROJECT/limit-untrusted-parse-dimensions.patch"
#
git -C "$PROJECT/repo" apply "$PROJECT/fix-squeeze-empty-inputs.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-blending-bounds.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-modular-pipeline-bounds.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-rct-grid-kind-mismatch.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-low-memory-pipeline-downsampling.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-entropy-restore-zero-rewind.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-extend-ref-frame-bounds.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-vardct-lf-rect-bounds.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-squeeze-avg-rect-channel-end.patch"

set -e
git clone-rev.sh https://github.com/libjxl/jxl-rs "$PROJECT/repo" 624ce908afcf8eb0dc2585a671535eaabb5d88cc
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

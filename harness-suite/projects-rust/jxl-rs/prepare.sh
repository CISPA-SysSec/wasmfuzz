set -e
git clone-rev.sh https://github.com/libjxl/jxl-rs "$PROJECT/repo" e1fc42e19cb217410c0218fe37edd32c598c6adf
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-decode-resource-limits.patch"
git -C "$PROJECT/repo" apply "$PROJECT/cap-untrusted-parse-dimensions.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-squeeze-empty-inputs.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-blending-bounds.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-modular-pipeline-bounds.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-rct-grid-kind-mismatch.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-splines-init-soft-fail.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-low-memory-pipeline-downsampling.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-group-size-for-channel-unwrap.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-entropy-restore-zero-rewind.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-extend-ref-frame-bounds.patch"

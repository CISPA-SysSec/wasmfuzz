set -e
git clone-rev.sh https://github.com/libjxl/jxl-rs "$PROJECT/repo" f370be423933628eb7f783f1b61d4c765eca5f79
git -C "$PROJECT/repo" apply "$PROJECT/port-disable-simd.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-decode-resource-limits.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-cheap-buffer-recycler.patch"
git -C "$PROJECT/repo" apply "$PROJECT/limit-untrusted-parse-dimensions.patch"
#
git -C "$PROJECT/repo" apply "$PROJECT/fix-squeeze-empty-inputs.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-flush-error-reference-frames.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-low-memory-pipeline-resent-channel.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-skipped-preview-frame.patch"

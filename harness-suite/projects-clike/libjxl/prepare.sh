set -e

git clone-rev.sh https://github.com/libjxl/libjxl "$PROJECT/repo" 12e4bf4087bcfc2a936596cade001f6a1f30b9ef --recursive
git -C "$PROJECT/repo" apply ../port-wasi-threads.patch
git -C "$PROJECT/repo" apply ../fix-convert-empty-primary-icc.patch
git -C "$PROJECT/repo" apply ../fix-lz77-distance-multiplier-empty-channels.patch
git -C "$PROJECT/repo" apply ../fix-streaming-forced-dots.patch
git -C "$PROJECT/repo" apply ../fix-butteraugli-loop-small-images.patch
git -C "$PROJECT/repo" apply ../fuzz-streaming-group-dim.patch
git -C "$PROJECT/repo" apply ../fuzz-streaming-lossy-no-default-patches.patch
git -C "$PROJECT/repo" apply ../fix-render-pipeline-partial-group-data.patch
git -C "$PROJECT/repo" apply ../fix-jpeg-recon-late-jbrd.patch
git -C "$PROJECT/repo" apply ../fix-modular-gaborish-patches-padding.patch
git -C "$PROJECT/repo" apply ../fuzz-streaming-gaborish-lossless-seams.patch
git -C "$PROJECT/repo" apply ../limit-djxl-wasm-memory-cap.patch

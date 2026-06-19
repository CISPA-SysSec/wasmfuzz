set -e
git clone-rev.sh https://github.com/etemesi254/zune-image "$PROJECT/repo" 43624422622918186141e04b6ed01ec80786bcbb
git -C "$PROJECT/repo" apply "$PROJECT/disable-fuzz-idct-wasm.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-png-roundtrip-fuzz.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-zcursor-read-overflow.patch"
git -C "$PROJECT/repo" apply "$PROJECT/cap-hdr-output-size.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-ppm-header-overflow.patch"
git -C "$PROJECT/repo" apply "$PROJECT/cap-psd-output-size.patch"
git -C "$PROJECT/repo" apply "$PROJECT/cap-qoi-output-size.patch"
git -C "$PROJECT/repo" apply "$PROJECT/cap-png-output-size.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-jpeg-mcu-upsampling-bounds.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-jpeg-worker-upsampling-bounds.patch"
git -C "$PROJECT/repo" apply "$PROJECT/decode-incremental-fuzz-wasm-cap.patch"

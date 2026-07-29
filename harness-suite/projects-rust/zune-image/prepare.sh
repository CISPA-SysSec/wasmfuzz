set -e
git clone-rev.sh https://github.com/etemesi254/zune-image "$PROJECT/repo" 8f1d383262d1df7b20d648dcf0e3a5d406ed7685
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
git -C "$PROJECT/repo" apply "$PROJECT/fix-bmp-log-macro-match-arm.patch"

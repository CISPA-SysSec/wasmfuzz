set -e
git clone-rev.sh https://github.com/etemesi254/zune-image "$PROJECT/repo" 1b1486a96a11264dd2ed809e48e316d5a241ee3e
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-disable-idct.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-png-roundtrip-api.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-zcursor-read-overflow.patch"
git -C "$PROJECT/repo" apply "$PROJECT/limit-hdr-output-size.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-ppm-header-overflow.patch"
git -C "$PROJECT/repo" apply "$PROJECT/limit-psd-output-size.patch"
git -C "$PROJECT/repo" apply "$PROJECT/limit-qoi-output-size.patch"
git -C "$PROJECT/repo" apply "$PROJECT/limit-png-output-size.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-jpeg-mcu-upsampling-bounds.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-jpeg-worker-upsampling-bounds.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-decode-incremental-wasm-cap.patch"

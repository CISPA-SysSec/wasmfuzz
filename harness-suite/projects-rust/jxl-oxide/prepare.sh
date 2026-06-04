set -e
git clone-rev.sh https://github.com/tirr-c/jxl-oxide.git "$PROJECT/repo" 4793a821d1a1893ce9ebd475b280a914d04f33df
git -C "$PROJECT/repo" apply ../fuzz-decode-resource-limits.patch
git -C "$PROJECT/repo" apply ../fix-wasi-render-wait-no-trace.patch
git -C "$PROJECT/repo" apply ../fix-dct-common-mutex-reentrancy.patch
git -C "$PROJECT/repo" apply ../fix-tracing-release-max-level-off.patch
git -C "$PROJECT/repo" apply ../fix-wasi-composite-drop-render-lock.patch
git -C "$PROJECT/repo" apply ../fix-blend-subgrid-bounds.patch
git -C "$PROJECT/repo" apply ../fix-blend-single-region-bounds.patch
git -C "$PROJECT/repo" apply ../fix-blend-empty-region.patch
git -C "$PROJECT/repo" apply ../fix-suggested-hdr-tf-missing-icc.patch
git -C "$PROJECT/repo" apply ../fix-adaptive-lf-smoothing-buffer-len.patch
git -C "$PROJECT/repo" apply ../fix-subgrid-range-saturating.patch
git -C "$PROJECT/repo" apply ../fix-gabor-region-bounds.patch
git -C "$PROJECT/repo" apply ../fix-upsample-jpeg-grayscale.patch
git -C "$PROJECT/repo" apply ../fix-modular-pass-shift-lookup.patch
git -C "$PROJECT/repo" apply ../fix-hlg-transfer-grayscale.patch
git -C "$PROJECT/repo" apply ../fix-blend-color-channel-mismatch.patch
git -C "$PROJECT/repo" apply ../fix-epf-region-contains.patch
git -C "$PROJECT/repo" apply ../fix-spline-point-count-overflow.patch
git -C "$PROJECT/repo" apply ../fix-xyb-transform-soft-fail.patch
# # Bug benchmark: Re-introduce NaN issue https://github.com/tirr-c/jxl-oxide/pull/485
# git -C "$PROJECT/repo" apply ../revert-fix-crash-with-NaNs-in-upsampling-485.patch
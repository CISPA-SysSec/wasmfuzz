set -e

git clone-rev.sh https://gitlab.freedesktop.org/poppler/poppler.git "$PROJECT/repo" d82831513d10d77ab2a6859d209dbd0f57395154
git clone-rev.sh https://github.com/madler/zlib.git "$PROJECT/zlib" 617e19a81f38c15ff04de9f86882f42ad8a8ffd1
git clone-rev.sh https://gitlab.freedesktop.org/freetype/freetype.git "$PROJECT/freetype" d4d00b890aab5970f291338b9de626ceafefbdec
git -C "$PROJECT/freetype" apply ../port-freetype-wasi-sjlj.patch
git -C "$PROJECT/freetype" apply ../fix-freetype-t42-glyph-index-bounds.patch
git -C "$PROJECT/repo" apply ../port-wasi-fuzzer-init.patch
git -C "$PROJECT/repo" apply ../port-wasi-object-incomplete-type.patch
git -C "$PROJECT/repo" apply ../port-wasi-gfile.patch
git -C "$PROJECT/repo" apply ../port-wasi-fuzzer-temp-file.patch
git -C "$PROJECT/repo" apply ../port-wasi-mutex.patch
git -C "$PROJECT/repo" apply ../fix-fdp-missing-cstdlib.patch
git -C "$PROJECT/repo" apply ../fix-jbig2-exported-symbol-count.patch
git -C "$PROJECT/repo" apply ../limit-jbig2-symbol-count.patch
git -C "$PROJECT/repo" apply ../fix-xref-copy-failure.patch
git -C "$PROJECT/repo" apply ../fix-memstream-substream-bounds.patch
git -C "$PROJECT/repo" apply ../fix-splashclip-int-bounds.patch
git -C "$PROJECT/repo" apply ../fix-textpool-unbounded-baseline-span.patch
git -C "$PROJECT/repo" apply ../fix-splash-coord-float-to-int.patch
git -C "$PROJECT/repo" apply ../fix-splashoutputdev-page-size-cast.patch
git -C "$PROJECT/repo" apply ../fix-setupbasefonts-repeated-search.patch
git -C "$PROJECT/repo" apply ../fix-movie-poster-appearance-xref.patch
git -C "$PROJECT/repo" apply ../fix-postscript-function-length-reserve.patch
git -C "$PROJECT/repo" apply ../fix-jbig2-expand-alloc-failure.patch
git -C "$PROJECT/repo" apply ../fix-xref-isrefencrypted-objstm-type.patch
git -C "$PROJECT/repo" apply ../fix-splashbitmap-alpha-alloc-failure.patch
git -C "$PROJECT/repo" apply ../fix-splash-masked-image-lookup-alloc.patch
git -C "$PROJECT/repo" apply ../fix-hints-length-beyond-file.patch
git -C "$PROJECT/repo" apply ../limit-stream-predictor-row-chunks.patch
# set up GlobalParams once in LLVMFuzzerInitialize instead of per input (perf)
git -C "$PROJECT/repo" apply ../fuzz-globalparams-once.patch

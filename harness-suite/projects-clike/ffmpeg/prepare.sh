set -e

apt-get update -y
apt-get install -y autoconf automake libtool pkg-config nasm yasm python3

# FFmpeg and codec dependencies (subset aligned with ffmpeg.wasm / OSS-Fuzz).
git clone-rev.sh https://github.com/FFmpeg/FFmpeg.git "$PROJECT/repo" 50276fac71863c3ffd6e3edfe765086103a695d5
git clone-rev.sh https://github.com/madler/zlib.git "$PROJECT/zlib" 617e19a81f38c15ff04de9f86882f42ad8a8ffd1
git clone-rev.sh https://gitlab.xiph.org/xiph/ogg.git "$PROJECT/ogg" 06a5e0262cdc28aa4ae6797627a783b5010440f0
git clone-rev.sh https://gitlab.xiph.org/xiph/opus.git "$PROJECT/opus" 316c675fa1c9982d76e9cdcba7231076f75047da
git clone-rev.sh https://gitlab.xiph.org/xiph/theora.git "$PROJECT/theora" 28fd5ec77f0ad0e07a371cef1047828116f6bd8a
git clone-rev.sh https://gitlab.xiph.org/xiph/vorbis.git "$PROJECT/vorbis" 1b75110b5a2754ba1931d82dd83cb822b266a21d
git clone-rev.sh https://chromium.googlesource.com/webm/libvpx "$PROJECT/libvpx" 0c7afa13cc76906a0895eb8661703373561b37c7

cp "$PROJECT/name_mappings.py" "$PROJECT/repo/"

git -C "$PROJECT/repo" apply ../fix-sws-yuv2rgb-x-table-overshoot.patch
git -C "$PROJECT/repo" apply ../fix-demux-decode-delay-stale-avctx.patch
git -C "$PROJECT/repo" apply ../fix-g723-1-parser-next-overflow.patch
git -C "$PROJECT/repo" apply ../fix-mov-stsd-entries-current-stream.patch
git -C "$PROJECT/repo" apply ../fix-avidec-sync-chunk-size-overflow.patch
git -C "$PROJECT/repo" apply ../fix-jpegxl-collect-box-pos-overflow.patch

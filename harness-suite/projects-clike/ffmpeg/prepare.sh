set -e

apt-get update -y
apt-get install -y autoconf automake libtool pkg-config nasm yasm python3

# FFmpeg and codec dependencies (subset aligned with ffmpeg.wasm / OSS-Fuzz).
git clone-rev.sh https://github.com/FFmpeg/FFmpeg.git "$PROJECT/repo" 903325e279b67156c3aa1f06ec5cb2378d9d004d
git clone-rev.sh https://github.com/madler/zlib.git "$PROJECT/zlib" e3dc0a85b7032e98380dec011bc8f2c2ee0d8fca
git clone-rev.sh https://gitlab.xiph.org/xiph/ogg.git "$PROJECT/ogg" 06a5e0262cdc28aa4ae6797627a783b5010440f0
git clone-rev.sh https://gitlab.xiph.org/xiph/opus.git "$PROJECT/opus" 328079cfdade069a2fce6db5501b8de75c97d060
git clone-rev.sh https://gitlab.xiph.org/xiph/theora.git "$PROJECT/theora" 28fd5ec77f0ad0e07a371cef1047828116f6bd8a
git clone-rev.sh https://gitlab.xiph.org/xiph/vorbis.git "$PROJECT/vorbis" 1b75110b5a2754ba1931d82dd83cb822b266a21d
git clone-rev.sh https://chromium.googlesource.com/webm/libvpx "$PROJECT/libvpx" d2413e2ca11039724ca33bb4d661ca2c94cb501e

cp "$PROJECT/name_mappings.py" "$PROJECT/repo/"

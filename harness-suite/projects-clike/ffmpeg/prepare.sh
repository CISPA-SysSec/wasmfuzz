set -e

apt-get update -y
apt-get install -y autoconf automake libtool pkg-config nasm yasm python3

# FFmpeg and codec dependencies (subset aligned with ffmpeg.wasm / OSS-Fuzz).
git clone-rev.sh https://github.com/FFmpeg/FFmpeg.git "$PROJECT/repo" 92cd5c97817be98361137e12fdba1f13db20f5c9
git clone-rev.sh https://github.com/madler/zlib.git "$PROJECT/zlib" e3dc0a85b7032e98380dec011bc8f2c2ee0d8fca
git clone-rev.sh https://gitlab.xiph.org/xiph/ogg.git "$PROJECT/ogg" 06a5e0262cdc28aa4ae6797627a783b5010440f0
git clone-rev.sh https://gitlab.xiph.org/xiph/opus.git "$PROJECT/opus" 3da9f7a6db1c05c3996cb363a9d1931a978bf1be
git clone-rev.sh https://gitlab.xiph.org/xiph/theora.git "$PROJECT/theora" 28fd5ec77f0ad0e07a371cef1047828116f6bd8a
git clone-rev.sh https://gitlab.xiph.org/xiph/vorbis.git "$PROJECT/vorbis" e3c9861ff096d52378e131ff8c334552e09cdffa
git clone-rev.sh https://chromium.googlesource.com/webm/libvpx "$PROJECT/libvpx" ade52487a37ef76a0f209bd39bea9fe67d6db4c4

cp "$PROJECT/name_mappings.py" "$PROJECT/repo/"

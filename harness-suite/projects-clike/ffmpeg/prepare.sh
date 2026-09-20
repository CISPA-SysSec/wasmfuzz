set -e

apt-get update -y
apt-get install -y autoconf automake libtool pkg-config nasm yasm python3

# FFmpeg and codec dependencies (subset aligned with ffmpeg.wasm / OSS-Fuzz).
git clone-rev.sh https://github.com/FFmpeg/FFmpeg.git "$PROJECT/repo" e7782ef185fefcc4ec087b98cedc7eee60d36100
git clone-rev.sh https://github.com/madler/zlib.git "$PROJECT/zlib" d81c2d7eb705c62294ba03299255672078e89115
git clone-rev.sh https://gitlab.xiph.org/xiph/ogg.git "$PROJECT/ogg" 06a5e0262cdc28aa4ae6797627a783b5010440f0
git clone-rev.sh https://gitlab.xiph.org/xiph/opus.git "$PROJECT/opus" 503d81b138d76621aae4b12786e90de48aa8db3a
git clone-rev.sh https://gitlab.xiph.org/xiph/theora.git "$PROJECT/theora" 28fd5ec77f0ad0e07a371cef1047828116f6bd8a
git clone-rev.sh https://gitlab.xiph.org/xiph/vorbis.git "$PROJECT/vorbis" 1b75110b5a2754ba1931d82dd83cb822b266a21d
git clone-rev.sh https://chromium.googlesource.com/webm/libvpx "$PROJECT/libvpx" 5e680f30801d03c21078f8c4b772464752516211

cp "$PROJECT/name_mappings.py" "$PROJECT/repo/"

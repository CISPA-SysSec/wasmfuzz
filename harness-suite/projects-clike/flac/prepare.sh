set -e
# upstream HEAD (1.5.0-34-ge94ff9f6); Chromium ships 1.4.2 (third_party/flac,
# README.chromium revision b32e5cbf9818ca23dd22aaa75522042c16ea7d17)
git clone-rev.sh https://github.com/xiph/flac.git "$PROJECT/repo" 59fa3402cb19b6b7c85b916f138cfb03c7b27504
git -C "$PROJECT/repo" apply "$PROJECT/port-decoder-no-exceptions.patch"
git -C "$PROJECT/repo" apply "$PROJECT/port-wasi-no-chown.patch"
git -C "$PROJECT/repo" apply "$PROJECT/port-seek-in-memory.patch"

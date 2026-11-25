set -e
# OTS and its dependencies (woff2, brotli, zlib, lz4 as vendored next to Firefox's gfx/ots)
# at upstream HEAD; Firefox ships OTS 62634335137d (gfx/ots/moz.yaml), Chromium 46bea98791.
git clone-rev.sh https://github.com/khaledhosny/ots.git "$PROJECT/repo" c5d249ce90ab0aa3e76eb0dfad28746f407201d0
git clone-rev.sh https://github.com/google/woff2.git "$PROJECT/woff2" 7b67e12355fe7da148db5c19d4261f0a498a9537
git clone-rev.sh https://github.com/google/brotli.git "$PROJECT/brotli" fed075f48eaffa447243a8e0452a88b103506118
git clone-rev.sh https://github.com/madler/zlib.git "$PROJECT/zlib" 617e19a81f38c15ff04de9f86882f42ad8a8ffd1
git clone-rev.sh https://github.com/lz4/lz4.git "$PROJECT/lz4" 4590271c5afad47b3e99a86712ec4c97174b033c

# Firefox's CFF charstring 64M-ops cap (gfx/ots/ots-cff-charstring-ops-limit.patch)
# is upstream since 2ee688e, so no local patch is needed.

set -e
# OTS and its dependencies (woff2, brotli, zlib, lz4 as vendored next to Firefox's gfx/ots)
# at upstream HEAD; Firefox ships OTS 62634335137d (gfx/ots/moz.yaml), Chromium 46bea98791.
git clone-rev.sh https://github.com/khaledhosny/ots.git "$PROJECT/repo" 62634335137d86473c84b20a8de9b9d97645bbd6
git clone-rev.sh https://github.com/google/woff2.git "$PROJECT/woff2" fb9c3379f2605b10f3e8f1d9636664ab5576775c
git clone-rev.sh https://github.com/google/brotli.git "$PROJECT/brotli" 11017d7812b0502005603cf0f3cce0054e885d72
git clone-rev.sh https://github.com/madler/zlib.git "$PROJECT/zlib" 767c4c947852e143f582c85f14cf573411df1b35
git clone-rev.sh https://github.com/lz4/lz4.git "$PROJECT/lz4" 0774d05537f9762f838f7ab541b7765f1a729cb5

# Firefox's local patch (gfx/ots/ots-cff-charstring-ops-limit.patch): caps CFF
# charstring execution at 64M ops. Mirrors the shipped configuration and avoids
# pathological-timeout inputs.
git -C "$PROJECT/repo" apply ../fuzz-firefox-cff-charstring-ops-limit.patch

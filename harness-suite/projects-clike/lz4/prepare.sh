set -e
# upstream HEAD; Firefox ships 1.10.0 (mozglue/static/lz4/README.mozilla). Chromium does not ship lz4.
git clone-rev.sh https://github.com/lz4/lz4.git "$PROJECT/repo" 0774d05537f9762f838f7ab541b7765f1a729cb5
# Firefox replaces lz4's bundled xxhash with upstream xxHash 0.8.3 (README.mozilla).
git clone-rev.sh https://github.com/Cyan4973/xxHash.git "$PROJECT/xxhash" 680bf463fa1ca0461b9a7c2dab7556e1f54cf4cf
cp "$PROJECT/xxhash/xxhash.c" "$PROJECT/xxhash/xxhash.h" "$PROJECT/repo/lib/"

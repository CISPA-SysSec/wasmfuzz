set -e
# upstream HEAD; Firefox ships 1.10.0 (mozglue/static/lz4/README.mozilla). Chromium does not ship lz4.
git clone-rev.sh https://github.com/lz4/lz4.git "$PROJECT/repo" 4590271c5afad47b3e99a86712ec4c97174b033c
git -C "$PROJECT/repo" apply ../fix-empty-output-last-token-ml-bits.patch
# Firefox replaces lz4's bundled xxhash with upstream xxHash 0.8.3 (README.mozilla).
git clone-rev.sh https://github.com/Cyan4973/xxHash.git "$PROJECT/xxhash" 2ec67caeb18ec15ae60c0853174331089acddfc0
cp "$PROJECT/xxhash/xxhash.c" "$PROJECT/xxhash/xxhash.h" "$PROJECT/repo/lib/"

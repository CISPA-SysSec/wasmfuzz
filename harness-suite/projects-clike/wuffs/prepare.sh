set -e

# Both clones are at upstream HEAD, which is the Wuffs v0.4 line. Chromium
# ships v0.3.5 instead: its third_party/wuffs/src is this same
# google/wuffs-mirror-release-c commit, but BUILD.gn compiles wuffs-v0.3.c.
git clone-rev.sh https://github.com/google/wuffs-mirror-release-c.git "$PROJECT/release" 7411f488fe2e2c205c3d3b3d28638b7356522930
# The mirror only carries release/c/*.c. The fuzzers live in google/wuffs,
# whose HEAD targets the v0.4 API.
git clone-rev.sh https://github.com/google/wuffs.git "$PROJECT/repo" f31d952b62fcd8abcc8d42908284f50097313bc8

# The fuzzers #include "release/c/wuffs-unsupported-snapshot.c" (the
# unreleased development snapshot). Replace it with the mirror's v0.4 release
# file (identical to google/wuffs HEAD's own release/c/wuffs-v0.4.c), so the
# harnesses fuzz released v0.4 code with the v0.4 fuzzers.
cp "$PROJECT/release/release/c/wuffs-v0.4.c" "$PROJECT/repo/release/c/wuffs-unsupported-snapshot.c"

git -C "$PROJECT/repo" apply ../port-fuzzlib-trap.patch
git -C "$PROJECT/repo" apply ../port-pixel-swizzler-no-mmap.patch

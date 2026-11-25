set -e

# Both clones are at upstream HEAD, which is the Wuffs v0.4 line. Chromium
# ships v0.3.5 instead: its third_party/wuffs/src is this same
# google/wuffs-mirror-release-c commit, but BUILD.gn compiles wuffs-v0.3.c.
git clone-rev.sh https://github.com/google/wuffs-mirror-release-c.git "$PROJECT/release" c55c7ceba7ef6560f7f6154be7db1c3a181e1321
# The mirror only carries release/c/*.c. The fuzzers live in google/wuffs,
# whose HEAD targets the v0.4 API.
git clone-rev.sh https://github.com/google/wuffs.git "$PROJECT/repo" a87f0bb85b9406d29f48a1c03b6f42c4585145f6

# The fuzzers #include "release/c/wuffs-unsupported-snapshot.c" (the
# unreleased development snapshot). Replace it with the mirror's v0.4 release
# file (identical to google/wuffs HEAD's own release/c/wuffs-v0.4.c), so the
# harnesses fuzz released v0.4 code with the v0.4 fuzzers.
cp "$PROJECT/release/release/c/wuffs-v0.4.c" "$PROJECT/repo/release/c/wuffs-unsupported-snapshot.c"

git -C "$PROJECT/repo" apply ../port-fuzzlib-trap.patch
git -C "$PROJECT/repo" apply ../port-pixel-swizzler-no-mmap.patch

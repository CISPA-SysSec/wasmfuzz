set -e
git clone-rev.sh https://github.com/harfbuzz/harfrust.git "$PROJECT/repo" 9849d82ac4cfc359d3cd2f5704ec8ec550303946

# Pinned to the read-fonts version harfrust's workspace resolves.
curl -fsSL -o "$PROJECT/read-fonts.crate" https://static.crates.io/crates/read-fonts/0.47.0/download
mkdir -p "$PROJECT/read-fonts"
tar -xzf "$PROJECT/read-fonts.crate" -C "$PROJECT/read-fonts" --strip-components=1
patch -d "$PROJECT/read-fonts" -p1 <"$PROJECT/fix-read-fonts-varc-region-count-alloc.patch"
rm -f "$PROJECT/read-fonts.crate"
git -C "$PROJECT/repo" apply "$PROJECT/port-vendored-crate-patches.patch"

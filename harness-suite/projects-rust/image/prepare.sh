set -e
git clone-rev.sh https://github.com/image-rs/image.git "$PROJECT/repo" f83dfb3ae63398fc2807eddde86c9fb3f6775d86
git -C "$PROJECT/repo" apply "$PROJECT/fix-icc-profile-allocation.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-ico-bmp-zero-height.patch"

# Pinned to versions resolved by `image` 0.25.9 for the fuzz workspace (`cargo tree -p image -i …`).
curl -fsSL -o "$PROJECT/zune-jpeg.crate" https://static.crates.io/crates/zune-jpeg/0.5.15/download
curl -fsSL -o "$PROJECT/image-webp.crate" https://static.crates.io/crates/image-webp/0.2.4/download
mkdir -p "$PROJECT/zune-jpeg" "$PROJECT/image-webp"
tar -xzf "$PROJECT/zune-jpeg.crate" -C "$PROJECT/zune-jpeg" --strip-components=1
tar -xzf "$PROJECT/image-webp.crate" -C "$PROJECT/image-webp" --strip-components=1
patch -d "$PROJECT/zune-jpeg" -p1 <"$PROJECT/zune-jpeg-mcu-scratch.patch"
patch -d "$PROJECT/image-webp" -p1 <"$PROJECT/image-webp-lossless-temp-limit.patch"
rm -f "$PROJECT/zune-jpeg.crate" "$PROJECT/image-webp.crate"

curl -fsSL -o "$PROJECT/png.crate" https://static.crates.io/crates/png/0.18.1/download
mkdir -p "$PROJECT/png"
tar -xzf "$PROJECT/png.crate" -C "$PROJECT/png" --strip-components=1
patch -d "$PROJECT/png" -p1 <"$PROJECT/fix-png-palette-partial.patch"
rm -f "$PROJECT/png.crate"

curl -fsSL -o "$PROJECT/tiff.crate" https://static.crates.io/crates/tiff/tiff-0.11.3.crate
mkdir -p "$PROJECT/tiff"
tar -xzf "$PROJECT/tiff.crate" -C "$PROJECT/tiff" --strip-components=1
patch -d "$PROJECT/tiff" -p1 <"$PROJECT/tiff-intermediate-row-limit.patch"
rm -f "$PROJECT/tiff.crate"

curl -fsSL -o "$PROJECT/moxcms.crate" https://static.crates.io/crates/moxcms/0.8.1/download
mkdir -p "$PROJECT/moxcms"
tar -xzf "$PROJECT/moxcms.crate" -C "$PROJECT/moxcms" --strip-components=1
patch -d "$PROJECT/moxcms" -p1 <"$PROJECT/fix-moxcms-trc-tag-overflow.patch"
rm -f "$PROJECT/moxcms.crate"

git -C "$PROJECT/repo" apply "$PROJECT/fix-jpeg-webp-image.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-tiff-fuzz-limits.patch"

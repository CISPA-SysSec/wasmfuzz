set -e

git clone-rev.sh https://code.videolan.org/videolan/dav2d.git "$PROJECT/repo" d036a6ec946a3fbf6c62a998363b351a7830117d
git -C "$PROJECT/repo" apply ../fix-wasi.patch

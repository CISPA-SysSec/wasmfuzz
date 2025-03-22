set -e
git clone-rev.sh https://github.com/etemesi254/zune-image "$PROJECT/repo" 4a073b12947f9d1003ae931b7b7cd9da2914d4d8
git -C "$PROJECT/repo" apply "$PROJECT/wasm.patch"


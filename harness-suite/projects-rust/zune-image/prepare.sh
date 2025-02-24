set -e
git clone-rev.sh https://github.com/etemesi254/zune-image "$PROJECT/repo" c9f333dd3f725e5fd044e0e6af37f2807485d35e
git -C "$PROJECT/repo" apply "$PROJECT/wasm.patch"


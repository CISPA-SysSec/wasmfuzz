set -e
git clone-rev.sh https://github.com/etemesi254/zune-image "$PROJECT/repo" c032bb73ace7b963bcb31db0267aadd3f39528e9
git -C "$PROJECT/repo" apply "$PROJECT/wasm.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-ppm-capacity-overflow.patch"


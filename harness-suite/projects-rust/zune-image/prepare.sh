set -e
git clone-rev.sh https://github.com/etemesi254/zune-image "$PROJECT/repo" 031f8b7032476458cba37ebe1ae09447a9e3746b
git -C "$PROJECT/repo" apply "$PROJECT/wasm.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-ppm-capacity-overflow.patch"


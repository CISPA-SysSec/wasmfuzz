set -e
git clone-rev.sh https://github.com/etemesi254/zune-image "$PROJECT/repo" ca5b0ef0cd3fe9535f875c904c8428e9f3706f41
git -C "$PROJECT/repo" apply "$PROJECT/wasm.patch"


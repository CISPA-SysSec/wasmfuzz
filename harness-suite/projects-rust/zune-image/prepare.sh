set -e
git clone-rev.sh https://github.com/etemesi254/zune-image "$PROJECT/repo" b6b1db81f10df4dbe22b427fb65aaa6b2b8b6b22
git -C "$PROJECT/repo" apply "$PROJECT/wasm.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-ppm-capacity-overflow.patch"


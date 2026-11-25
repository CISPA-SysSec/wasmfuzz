set -e
git clone-rev.sh https://github.com/nothings/stb.git "$PROJECT/repo" 6b5799bae8a1fe3792691ef4b72ae26434c3e799
git -C "$PROJECT/repo" apply ../fix-jpeg-huff-fast-symbol-255.patch

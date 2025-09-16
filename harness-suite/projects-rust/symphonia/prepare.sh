set -e
git clone-rev.sh https://github.com/pdeljanov/symphonia.git "$PROJECT/repo" 46b59dc35b677406fada42fd6390971ebc8ae40c
git -C "$PROJECT/repo" apply "$PROJECT/fix-step-by.patch"

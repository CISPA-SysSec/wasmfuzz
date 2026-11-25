set -e
apt-get update && apt-get install -y ruby rake bison
git clone-rev.sh https://github.com/mruby/mruby.git "$PROJECT/repo" 087c688517541ea878b3370c40f3a545e7fcd197
git -C "$PROJECT/repo" apply ../port-wasi-throw-exit-testcase.patch
git -C "$PROJECT/repo" apply ../fix-send-method-missing-self-recursion.patch

set -e
git clone-rev.sh https://github.com/astral-sh/ruff.git "$PROJECT/repo" 5d805dce45cb1d1f62bca58a3b2914607ad15939
git -C "$PROJECT/repo" apply "$PROJECT/port-disable-zstd.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-harness-crashes.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-tstring-unparse-escaped-quote.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-formatter-unary-comment-idempotency.patch"

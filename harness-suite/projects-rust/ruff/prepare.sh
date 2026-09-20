set -e
git clone-rev.sh https://github.com/astral-sh/ruff.git "$PROJECT/repo" 12446563435d6c03f1974efc3ebc30422b27ecf5
git -C "$PROJECT/repo" apply "$PROJECT/port-disable-zstd.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-harness-crashes.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-tstring-unparse-escaped-quote.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-formatter-unary-comment-idempotency.patch"

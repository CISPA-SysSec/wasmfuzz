set -e
git clone-rev.sh https://github.com/astral-sh/ruff.git "$PROJECT/repo" 162c08c8fa5fa519f4ae90838cf9e993397fb3cc
git -C "$PROJECT/repo" apply "$PROJECT/port-disable-zstd.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-harness-crashes.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-tstring-unparse-escaped-quote.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-formatter-unary-comment-idempotency.patch"

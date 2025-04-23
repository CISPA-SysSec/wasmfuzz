set -e
git clone-rev.sh https://github.com/kivikakk/comrak.git "$PROJECT/repo" ee3d0f44261c9172c8d4ccbcb75ee92e71d90c1c
git -C "$PROJECT/repo" apply "$PROJECT/fix-harnesses.patch"

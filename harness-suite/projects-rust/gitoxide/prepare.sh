set -e
git clone-rev.sh https://github.com/Byron/gitoxide.git "$PROJECT/repo" 1cfe577d461293879e91538dbc4bbfe01722e1e8
git -C "$PROJECT/repo" apply "$PROJECT/disable-incompatible.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-workspace-lints.patch"

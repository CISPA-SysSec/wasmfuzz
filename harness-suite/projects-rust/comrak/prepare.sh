set -e
git clone-rev.sh https://github.com/kivikakk/comrak.git "$PROJECT/repo" 32b4f7d55f4f8da27da19de9e458471815fda2c4
git -C "$PROJECT/repo" apply ../fix-harness-all_options.patch

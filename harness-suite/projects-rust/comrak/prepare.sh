set -e
git clone-rev.sh https://github.com/kivikakk/comrak.git "$PROJECT/repo" 97b0257975b622e2709ea97dcae6ddf22eeb7ba5
# cli_default deserialised the syntect syntax and theme dumps for every input.
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-cli-default-load-syntect-once.patch"

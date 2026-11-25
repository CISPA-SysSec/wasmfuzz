set -e
git clone-rev.sh https://github.com/Byron/gitoxide.git "$PROJECT/repo" 9abb53183a296185fc4e98376bc4ab895f39c2fe
git -C "$PROJECT/repo" apply "$PROJECT/port-disable-incompatible-fuzz.patch"
git -C "$PROJECT/repo" apply "$PROJECT/port-wasi-path-convert.patch"
# prepare Debug-formatted six std Commands per input (std fmt code, not gix-command).
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-prepare-skip-command-debug.patch"

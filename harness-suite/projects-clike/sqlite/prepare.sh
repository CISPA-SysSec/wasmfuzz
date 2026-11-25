set -e
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y make autoconf automake libtool curl tcl tcl-dev
DEBIAN_FRONTEND=noninteractive apt-get install -y clang

git clone-rev.sh https://github.com/sqlite/sqlite "$PROJECT/repo" 795e28a89e40246b7029f62440519229109c0503
git -C "$PROJECT/repo" apply ../fix-rename-star-full-join.patch
git -C "$PROJECT/repo" apply ../fix-trigger-fk-column-overlap.patch
git -C "$PROJECT/repo" apply ../fix-omit-orderby-windows.patch
git -C "$PROJECT/repo" apply ../fix-union-limit1-left-compound.patch
# sqlite3_initialize() ran lazily inside the first input.
git -C "$PROJECT/repo" apply ../fuzz-ossfuzz-initialize-once.patch

# The *_debug modules (SQLITE_DEBUG=1, see build.sh) build from a copy of the
# patched tree with two more patches that only matter for debug builds.
cp -a "$PROJECT/repo" "$PROJECT/repo-debug"
git -C "$PROJECT/repo-debug" apply ../port-wasi-sqlite-debug.patch
git -C "$PROJECT/repo-debug" apply ../fix-filestat-memjournal.patch

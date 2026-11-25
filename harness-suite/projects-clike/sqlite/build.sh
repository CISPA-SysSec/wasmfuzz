#!/bin/bash
set -e +x
# source set-buildflags.sh

cd "$PROJECT/repo"
export SRC="$PROJECT/repo"


export CC=clang CXX=clang++
export CFLAGS="-g -gdwarf-5 -gembed-source -O2 -flto=thin -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"

# Limit max length of data blobs and sql queries to prevent irrelevant OOMs.
# Also limit max memory page count to avoid creating large databases.
export CFLAGS="$CFLAGS -DSQLITE_MAX_LENGTH=125000 \
               -DSQLITE_MAX_SQL_LENGTH=125000 \
               -DSQLITE_MAX_MEMORY=24414 \
               -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 \
               -DSQLITE_MAX_PAGE_COUNT=16"

# The *_debug modules link a second library build with SQLite's internal
# checks (assert(), ALWAYS()/NEVER(), sqlite3VdbeMemIsValid() and friends),
# from repo-debug (prepare.sh). Not configure's --debug: that also switches to
# -O0, memsys5 and the select/where tracers. Without --debug, configure puts
# -DNDEBUG in front of $CFLAGS, so undo it. The debug-only trace pragmas
# (vdbe_*, parser_trace) are denied by both harnesses' authorizers;
# sql_trace prints one line per statement (dropped by the fuzzer).
DEBUG_FLAGS="-UNDEBUG -DSQLITE_DEBUG=1"
DEBUG_SRC="$PROJECT/repo-debug"

export WASI_SDK_PREFIX="/wasi-sdk/"
./configure \
        --disable-amalgamation \
	--with-wasi-sdk="$WASI_SDK_PREFIX" \
	$CONFIGUREFLAGS
	# --disable-shared \

make -j"$(nproc)"

(
    cd "$DEBUG_SRC"
    CFLAGS="$CFLAGS $DEBUG_FLAGS" ./configure \
        --disable-amalgamation \
        --with-wasi-sdk="$WASI_SDK_PREFIX" \
        $CONFIGUREFLAGS
    make -j"$(nproc)"
)

source set-buildflags.sh
$CC $CFLAGS -I. test/ossfuzz.c \
    -o /out/sqlite-ossfuzz.wasm \
    $LIB_FUZZING_ENGINE libsqlite3.a
$CC $CFLAGS -I. "$PROJECT/dbsql_fuzz.c" \
    -o /out/sqlite-dbsql.wasm \
    $LIB_FUZZING_ENGINE libsqlite3.a

cd "$DEBUG_SRC"
$CC $CFLAGS $DEBUG_FLAGS -I. test/ossfuzz.c \
    -o /out/sqlite-ossfuzz_debug.wasm \
    $LIB_FUZZING_ENGINE libsqlite3.a
$CC $CFLAGS $DEBUG_FLAGS -I. "$PROJECT/dbsql_fuzz.c" \
    -o /out/sqlite-dbsql_debug.wasm \
    $LIB_FUZZING_ENGINE libsqlite3.a

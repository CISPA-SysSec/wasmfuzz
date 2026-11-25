/*
** Combined database + SQL fuzz target for SQLite.
**
** The input uses the dbsqlfuzz text format that SQLite's own dbsqlfuzz
** fuzzer emits and test/fuzzcheck.c replays ("--load-dbsql", isDbSql(),
** decodeDatabase()), so cases from test/fuzzdata8.db work as seeds:
**
**   <database as hex text>\n--\n<SQL script>
**
** Database part: every hex digit pair is the next byte of the database
** image; "[NNNN]" (hex) moves the write cursor to byte offset NNNN; all other
** characters are ignored.  The image is zero-filled and its size rounded up
** to a multiple of 4096 bytes.  The first "\n--\n" ends the database part.
**
** As in dbsqlfuzz, header bytes 72..75 of the image toggle dbconfig settings
** and bytes 76..79 are the SQLITE_TESTCTRL_OPTIMIZATIONS mask.  The database
** is loaded with sqlite3_deserialize() into an in-memory connection and the
** script runs one complete statement at a time (prepare/step, errors
** ignored).  Nothing touches the filesystem: ATTACH is limited to in-memory
** databases.  Runtime is bounded by a VM-step budget in the progress handler.
*/
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "sqlite3.h"

/* 16 pages (SQLITE_MAX_PAGE_COUNT in build.sh) of the largest page size. */
#define MX_FILE_SZ (16 * 65536)
/* Progress handler period (VM ops) and budget (calls) per test case. */
#define PROGRESS_PERIOD 10
#define PROGRESS_MAX_CALLS 10000

typedef struct FuzzCtx {
  unsigned nCb;
} FuzzCtx;

static int progress_handler(void *pClientData) {
  FuzzCtx *p = (FuzzCtx *)pClientData;
  p->nCb++;
  return p->nCb >= PROGRESS_MAX_CALLS;
}

static unsigned char hexToInt(unsigned int h) {
  h += 9 * (1 & (h >> 6));
  return h & 0xf;
}

static int isHex(unsigned char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
         (c >= 'A' && c <= 'F');
}

/* "[NNNN]" at zIn[0]: set the half-byte cursor to 2*0xNNNN. */
static int isOffset(const unsigned char *zIn, size_t nIn, size_t *pK,
                    size_t *pI) {
  size_t i;
  size_t k = 0;
  for (i = 1; i < nIn && zIn[i] != ']'; i++) {
    if (!isHex(zIn[i])) return 0;
    k = k * 16 + hexToInt(zIn[i]);
    if (k > MX_FILE_SZ) return 0;
  }
  if (i == nIn) return 0;
  *pK = 2 * k;
  *pI += i;
  return 1;
}

/* fuzzcheck.c decodeDatabase(): returns the offset of the SQL text, or -1. */
static long decodeDatabase(const unsigned char *zIn, size_t n,
                           unsigned char **paDb, size_t *pnDb) {
  unsigned char *a, *aNew;
  size_t nAlloc = 4096;
  size_t i, j, k, mx = 0;
  unsigned char b = 0;
  if (n < 4) return -1;
  a = sqlite3_malloc64(nAlloc);
  if (a == 0) return -1;
  memset(a, 0, nAlloc);
  for (i = k = 0; i < n; i++) {
    unsigned char c = zIn[i];
    if (isHex(c)) {
      k++;
      if (k & 1) {
        b = hexToInt(c) * 16;
      } else {
        b += hexToInt(c);
        j = k / 2 - 1;
        if (j >= MX_FILE_SZ) {
          sqlite3_free(a);
          return -1;
        }
        if (j >= nAlloc) {
          size_t newSize = nAlloc * 2;
          if (newSize <= j) newSize = (j + 4096) & ~(size_t)4095;
          if (newSize > MX_FILE_SZ) newSize = MX_FILE_SZ;
          aNew = sqlite3_realloc64(a, newSize);
          if (aNew == 0) {
            sqlite3_free(a);
            return -1;
          }
          a = aNew;
          memset(a + nAlloc, 0, newSize - nAlloc);
          nAlloc = newSize;
        }
        if (j >= mx) mx = (j + 4096) & ~(size_t)4095;
        a[j] = b;
      }
    } else if (c == '[' && i + 3 < n && isOffset(zIn + i, n - i, &k, &i)) {
      continue;
    } else if (c == '\n' && i + 4 < n && memcmp(zIn + i, "\n--\n", 4) == 0) {
      i += 4;
      break;
    }
  }
  *pnDb = mx;
  *paDb = a;
  return (long)i;
}

/* dbsqlfuzz: bits of header bytes 72..75 toggle these settings. */
static const struct {
  unsigned int mask;
  int iSetting;
} aDbConfigSettings[] = {
    {0x0001, SQLITE_DBCONFIG_ENABLE_FKEY},
    {0x0002, SQLITE_DBCONFIG_ENABLE_TRIGGER},
    {0x0004, SQLITE_DBCONFIG_ENABLE_VIEW},
    {0x0008, SQLITE_DBCONFIG_ENABLE_QPSG},
    {0x0010, SQLITE_DBCONFIG_TRIGGER_EQP},
    {0x0020, SQLITE_DBCONFIG_DEFENSIVE},
    {0x0040, SQLITE_DBCONFIG_WRITABLE_SCHEMA},
    {0x0080, SQLITE_DBCONFIG_LEGACY_ALTER_TABLE},
    {0x0100, SQLITE_DBCONFIG_STMT_SCANSTATUS},
    {0x0200, SQLITE_DBCONFIG_REVERSE_SCANORDER},
#ifdef SQLITE_DBCONFIG_STRICT_AGGREGATE
    {0x0400, SQLITE_DBCONFIG_STRICT_AGGREGATE},
#endif
    {0x0800, SQLITE_DBCONFIG_DQS_DML},
    {0x1000, SQLITE_DBCONFIG_DQS_DDL},
    {0x2000, SQLITE_DBCONFIG_TRUSTED_SCHEMA},
};

static void toggleDbConfig(sqlite3 *db, int iSetting) {
  int v = 0;
  sqlite3_db_config(db, iSetting, -1, &v);
  sqlite3_db_config(db, iSetting, !v, 0);
}

/* Deny debug output pragmas, sleeping pragmas and file-backed ATTACH. */
static int block_troublesome_sql(void *pNotUsed, int eCode, const char *zArg1,
                                 const char *zArg2, const char *zArg3,
                                 const char *zArg4) {
  (void)pNotUsed;
  (void)zArg3;
  (void)zArg4;
  switch (eCode) {
    case SQLITE_PRAGMA:
      if (sqlite3_stricmp("busy_timeout", zArg1) == 0 &&
          (zArg2 == 0 || strtoll(zArg2, 0, 0) > 100 ||
           strtoll(zArg2, 0, 10) > 100)) {
        return SQLITE_DENY;
      }
      if (sqlite3_strnicmp("vdbe_", zArg1, 5) == 0 ||
          sqlite3_stricmp("parser_trace", zArg1) == 0 ||
          sqlite3_stricmp("temp_store_directory", zArg1) == 0) {
        return SQLITE_DENY;
      }
      break;
    case SQLITE_ATTACH:
      if (zArg1 == 0) return SQLITE_DENY;
      if (strcmp(zArg1, ":memory:") == 0) return SQLITE_OK;
      if (sqlite3_strglob("file:*[?]vfs=memdb", zArg1) == 0 &&
          sqlite3_strglob("file:*[^/a-zA-Z0-9_.]*[?]vfs=memdb", zArg1) != 0) {
        return SQLITE_OK;
      }
      return SQLITE_DENY;
  }
  return SQLITE_OK;
}

static void runStatement(sqlite3 *db, const char *zSql) {
  sqlite3_stmt *pStmt = 0;
  while (*zSql == ' ' || (*zSql >= '\t' && *zSql <= '\r')) zSql++;
  if (zSql[0] == 0) return;
  if (sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0) == SQLITE_OK) {
    while (sqlite3_step(pStmt) == SQLITE_ROW) {
    }
  }
  sqlite3_finalize(pStmt);
}

/* sqlite3_initialize()'s one-time setup belongs to startup, not to the first input. */
int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  sqlite3_initialize();
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  sqlite3 *db = 0;
  unsigned char *aDb = 0;
  size_t nDb = 0;
  long iSql;
  size_t nSql, i, j;
  char *zSql;
  unsigned int dbFlags = 0, dbOpt = 0;
  FuzzCtx cx;

  if (size < 10) return 0;
  if (sqlite3_initialize()) return 0;
  /* The build's SQLITE_MAX_MEMORY default is tiny; same limit as ossfuzz.c. */
  sqlite3_hard_heap_limit64(20000000);
  iSql = decodeDatabase(data, size, &aDb, &nDb);
  if (iSql < 0) return 0;
  if (nDb >= 80) {
    dbFlags = ((unsigned)aDb[72] << 24) | ((unsigned)aDb[73] << 16) |
              ((unsigned)aDb[74] << 8) | aDb[75];
    dbOpt = ((unsigned)aDb[76] << 24) | ((unsigned)aDb[77] << 16) |
            ((unsigned)aDb[78] << 8) | aDb[79];
  }
  nSql = size - (size_t)iSql;

  if (sqlite3_open_v2(":memory:", &db,
                      SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                          SQLITE_OPEN_MEMORY,
                      0)) {
    sqlite3_free(aDb);
    sqlite3_close(db);
    return 0;
  }
  sqlite3_test_control(SQLITE_TESTCTRL_OPTIMIZATIONS, db, dbOpt);
  for (i = 0; i < sizeof(aDbConfigSettings) / sizeof(aDbConfigSettings[0]);
       i++) {
    if (dbFlags & aDbConfigSettings[i].mask) {
      toggleDbConfig(db, aDbConfigSettings[i].iSetting);
    }
  }

  memset(&cx, 0, sizeof(cx));
  sqlite3_progress_handler(db, PROGRESS_PERIOD, progress_handler, &cx);
  sqlite3_limit(db, SQLITE_LIMIT_VDBE_OP, 25000);
  sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 50000);
  sqlite3_limit(db, SQLITE_LIMIT_EXPR_DEPTH, 500);
  sqlite3_limit(db, SQLITE_LIMIT_LIKE_PATTERN_LENGTH, 100);

  /* memdb has no WAL: present a WAL-mode header as rollback mode. */
  if (nDb >= 20 && aDb[18] == 2 && aDb[19] == 2) aDb[18] = aDb[19] = 1;
  if (nDb == 0) {
    sqlite3_free(aDb);
  } else if (sqlite3_deserialize(db, "main", aDb, nDb, nDb,
                                 SQLITE_DESERIALIZE_RESIZEABLE |
                                     SQLITE_DESERIALIZE_FREEONCLOSE)) {
    goto finished; /* deserialize frees aDb on failure */
  }
  {
    sqlite3_int64 x = MX_FILE_SZ;
    sqlite3_file_control(db, "main", SQLITE_FCNTL_SIZE_LIMIT, &x);
  }
  /* After deserialize, which itself runs an ATTACH internally. */
  sqlite3_set_authorizer(db, block_troublesome_sql, 0);

  zSql = sqlite3_malloc64(nSql + 1);
  if (zSql == 0) goto finished;
  memcpy(zSql, data + iSql, nSql);
  zSql[nSql] = 0;
  for (i = j = 0; zSql[i]; i++) {
    if (zSql[i] == ';') {
      char cSaved = zSql[i + 1];
      zSql[i + 1] = 0;
      if (sqlite3_complete(zSql + j)) {
        runStatement(db, zSql + j);
        j = i + 1;
      }
      zSql[i + 1] = cSaved;
      if (cx.nCb >= PROGRESS_MAX_CALLS) break;
    }
  }
  if (j < i && cx.nCb < PROGRESS_MAX_CALLS) runStatement(db, zSql + j);
  sqlite3_free(zSql);

finished:
  sqlite3_close(db);
  return 0;
}

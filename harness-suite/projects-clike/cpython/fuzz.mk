# Included after CPython's generated Makefile: builds the _xxtestfuzz targets
# against the static libpython, with the toolchain and module lists configure
# chose. FUZZ_LDFLAGS comes from set-buildflags.sh.
FUZZ_SRC = $(srcdir)/Modules/_xxtestfuzz/fuzzer.c

fuzz-%.o: $(FUZZ_SRC) pyconfig.h
	$(CC) -c $(PY_STDMODULE_CFLAGS) -D_Py_FUZZ_ONE -D_Py_FUZZ_$* -o $@ $(FUZZ_SRC)

fuzz-%.wasm: fuzz-%.o $(LIBRARY)
	$(LINKCC) $(CONFIGURE_CFLAGS) $(PY_LDFLAGS) $(FUZZ_LDFLAGS) -o $@ $< $(LIBRARY) $(LIBS) $(MODLIBS) $(SYSLIBS)

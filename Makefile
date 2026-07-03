EMACS      = emacs
MINGW_CC   = x86_64-w64-mingw32-gcc
PKG_CONFIG ?= pkg-config

SODIUM_CFLAGS := $(shell $(PKG_CONFIG) --cflags libsodium 2>/dev/null)
SODIUM_LIBS   := $(shell $(PKG_CONFIG) --libs libsodium 2>/dev/null || echo -lsodium)
SODIUM_LIBDIR := $(shell $(PKG_CONFIG) --variable=libdir libsodium 2>/dev/null)

CFLAGS  = -std=c99 -Wall -Wextra -O2 -fpic $(SODIUM_CFLAGS)
LDFLAGS = $(SODIUM_LIBS)
# Embed the libsodium directory as rpath so the module finds its
# dependency even when Emacs was built against a different loader
# environment (e.g. a nix-built Emacs on CI).  Not used for the
# Windows (PE) build, which has no rpath concept.
ifneq ($(SODIUM_LIBDIR),)
UNIX_LDFLAGS = $(LDFLAGS) -Wl,-rpath,$(SODIUM_LIBDIR)
else
UNIX_LDFLAGS = $(LDFLAGS)
endif

MODULE_SUFFIX := $(shell $(EMACS) -batch --eval '(princ module-file-suffix)' 2>/dev/null)
ifeq ($(MODULE_SUFFIX),)
MODULE_SUFFIX := .so
endif
MODULE := libsodium$(MODULE_SUFFIX)

all: $(MODULE) sodium.elc
linux: libsodium.so sodium.elc
windows: libsodium.dll sodium.elc

libsodium.so: libsodium.c
	$(CC) -shared $(CFLAGS) $^ $(UNIX_LDFLAGS) -o $@

libsodium.dylib: libsodium.c
	$(CC) -shared $(CFLAGS) $^ $(UNIX_LDFLAGS) -o $@

libsodium.dll: libsodium.c
	$(MINGW_CC) -shared $(CFLAGS) $^ $(LDFLAGS) -o $@

sodium.elc: sodium.el
	$(EMACS) -Q -batch -L . -f batch-byte-compile $<

sodium-box-demo.elc: sodium-box-demo.el
	$(EMACS) -Q -batch -L . -f batch-byte-compile $<

box-demo: sodium-box-demo.elc sodium.elc $(MODULE)
	$(EMACS) -Q -L . -l $< -f sodium-box-demo

test: $(MODULE) sodium.elc
	$(EMACS) -Q -batch -L . -l sodium-tests.el -f ert-run-tests-batch-and-exit

clean:
	$(RM) libsodium.so libsodium.dylib libsodium.dll sodium.elc sodium-box-demo.elc

.PHONY: clean all linux windows test box-demo

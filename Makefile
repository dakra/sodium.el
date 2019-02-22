EMACS    = emacs
MINGW_CC = x86_64-w64-mingw32-gcc
CFLAGS   = -std=c99 -s -Wall -Wextra -O3 -fpic
LDFLAGS  = -lsodium

MODULE_SUFFIX := $(shell $(EMACS) -batch --eval '(princ module-file-suffix)')

all: libsodium.so sodium.elc
linux: libsodium.so sodium.elc
windows: libsodium.dll sodium.elc

libsodium.so: libsodium.c
	$(CC) -shared $(CFLAGS) $(LDFLAGS) -o $@ $^

libsodium.dll: libsodium.c
	$(MINGW_CC) -shared $(CFLAGS) $(LCDFLAGS) -o $@ $^

sodium.elc: sodium.el
	$(EMACS) -Q -batch -L . -f batch-byte-compile $<

sodium-box-demo.elc: sodium-box-demo.el
	$(EMACS) -Q -batch -L . -f batch-byte-compile $<

box-demo: sodium-box-demo.elc sodium.elc libsodium$(MODULE_SUFFIX)
	$(EMACS) -Q -L . -l $< -f sodium-box-demo

clean:
	$(RM) libsodium.so libsodium.dll sodium.elc sodium-box-demo.elc

.PHONY: clean all linux windows

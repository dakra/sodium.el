EMACS    = emacs
MINGW_CC = x86_64-w64-mingw32-gcc
CFLAGS   = -std=c99 -s -Wall -Wextra -O3 -fpic
LDFLAGS  = -lsodium

MODULE_SUFFIX := $(shell $(EMACS) -batch --eval '(princ module-file-suffix)')

all: sodium.so
linux: sodium.so

sodium.so: sodium.c
	$(CC) -shared $(CFLAGS) $(LDFLAGS) -o $@ $^

sodium-box-demo.elc: sodium-box-demo.el
	$(EMACS) -Q -batch -L . -f batch-byte-compile $<

run: sodium-box-demo.elc sodium$(MODULE_SUFFIX)
	$(EMACS) -Q -L . -l $< -f sodium-box-demo

clean:
	$(RM) sodium.so sodium.dll sodium-box-demo.elc

.PHONY: clean all linux

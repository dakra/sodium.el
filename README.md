# Emacs bindings for libsodium

Emacs dynamic module exposing a high level interface to libsodium's
[crypto_box API](https://libsodium.gitbook.io/doc/public-key_cryptography/authenticated_encryption)
(X25519 + XSalsa20-Poly1305 authenticated public-key encryption), the
same construction used by the
[KeePassXC browser protocol](https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md).

Works on Linux and macOS with Emacs 28.1+ (built with module support).

## Requirements

- Emacs 28.1 or newer, built with dynamic module support
- libsodium and pkg-config:
  - macOS: `brew install libsodium pkg-config`
  - Debian/Ubuntu: `apt install libsodium-dev pkg-config`

## Install

Ensure that `sodium.el` is somewhere in your load path. Then

```elisp
(require 'sodium)
```

If the dynamic module (`sodium-module.so`/`.dylib`) is not compiled
yet, sodium offers to compile it for you on first load (in
non-interactive sessions it compiles automatically).  You can also
build it yourself with `make` or `M-x sodium-module-compile`.

If you use [Borg](https://github.com/emacscollective/borg),
make sure to execute `make` in you `.gitmodules` `build-step`
like this

```
[submodule "sodium"]
	path = lib/sodium
	url = git@github.com:dakra/sodium.el.git
	build-step = make
```

## API

All keys, nonces and ciphertexts cross the API as base64 strings.

- `(sodium-box-keypair)` → alist `((pk . "…") (sk . "…"))`
- `(sodium-box-make-nonce)` → new random nonce
- `(sodium-increment NONCE)` → nonce incremented by one (little-endian, constant time)
- `(sodium-box MSG NONCE PK SK)` → ciphertext
- `(sodium-box-open CIPHER NONCE PK SK)` → decrypted message

Constants: `sodium-box-macbytes`, `sodium-box-noncebytes`,
`sodium-box-publickeybytes`, `sodium-box-secretkeybytes`.
(`sodium-box-maxbytes` is a deprecated alias of `sodium-box-macbytes`.)

### Error handling

Invalid input (malformed base64, wrong-length keys/nonces) and failed
decryption (forged or corrupted messages) signal a `sodium-error`
instead of returning nil (which versions before 0.2 did):

```elisp
(condition-case err
    (sodium-box-open cipher nonce pk sk)
  (sodium-error (message "Decryption failed: %s" (cadr err))))
```

### Caveats

Messages are Emacs strings and are encrypted in their UTF-8 encoding;
embedded NUL bytes are fine, but arbitrary (non-UTF-8) binary blobs
are not representable across the module boundary.

## Usage

You can see `sodium-box-demo.el` for a simple example:
(Run the box-demo with `make box-demo`)

``` emacs-lisp
(require 'sodium)

(let* ((nonce  (sodium-box-make-nonce))
       (bob    (sodium-box-keypair))
       (bob-pk (cdr (assoc 'pk bob)))
       (bob-sk (cdr (assoc 'sk bob)))
       (alice    (sodium-box-keypair))
       (alice-pk (cdr (assoc 'pk alice)))
       (alice-sk (cdr (assoc 'sk alice)))
       (msg "Hello World!")
       encrypted decrypted)
  (message "Encrypting message '%s'" msg)
  (setq encrypted (sodium-box msg nonce bob-pk alice-sk))
  (message "Decrypt message '%s'" encrypted)
  (setq decrypted (sodium-box-open encrypted nonce alice-pk bob-sk))
  (message "Decrypted message '%s'" decrypted))
```

## Tests

Run the ERT test suite with

```
make test
```

## Thanks

@jedisct1 for [libsodium](https://github.com/jedisct1/libsodium)
and for [reviewing](https://github.com/dakra/sodium.el/issues/1) an early
version of this module.

Emacs module code was taken from/inspired by:
- https://phst.eu/emacs-modules
- https://github.com/skeeto/joymacs
- Looking at module code from https://github.com/syohex
- Emacs libgit2 bindings https://github.com/magit/libegit2
- http://diobla.info/blog-archive/modules-tut.html
- https://github.com/jkitchin/emacs-modules

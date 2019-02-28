# Emacs bindings for libsodium

This module is in alpha, works only in Linux with Emacs 25+
and only exposes a high level interface to the
[crypto_box API](https://libsodium.gitbook.io/doc/public-key_cryptography/authenticated_encryption).

## Install

Run `make` and ensure that `sodium.el` is somewhere in your load path. Then

```elisp
(require 'sodium)
```

If you use [Borg](https://github.com/emacscollective/borg),
make sure to execute `make` in you `.gitmodules` `build-step`
like this

```
[submodule "sodium"]
	path = lib/sodium
	url = git@github.com:dakra/sodium.el.git
	build-step = make
```


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

## Thanks
@jedisct1 for [libsodium](https://github.com/jedisct1/libsodium)

Emacs module code was taken from/inspired by:
- https://phst.eu/emacs-modules
- https://github.com/skeeto/joymacs
- Looking at module code from https://github.com/syohex
- Emacs libgit2 bindings https://github.com/magit/libegit2
- http://diobla.info/blog-archive/modules-tut.html
- https://github.com/jkitchin/emacs-modules

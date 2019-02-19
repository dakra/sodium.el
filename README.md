# Emacs bindings for libsodium

This module is in alpha, works only in Linux with Emacs 25+
and only exposes a high level interface to the
[crypto_box API](https://libsodium.gitbook.io/doc/public-key_cryptography/authenticated_encryption).

## Usage
You can see `sodium-box-demo.el` for a simple example:
``` emacs-lisp
(require 'sodium)

(let* ((nonce  (sodium-box-make-nonce))
       (bob    (sodium-box-make-keypair))
       (bob-pk (cdr (assoc 'pk bob)))
       (bob-sk (cdr (assoc 'sk bob)))
       (eve    (sodium-box-make-keypair))
       (eve-pk (cdr (assoc 'pk eve)))
       (eve-sk (cdr (assoc 'sk eve)))
       (msg "Hello World!")
       encrypted decrypted)
    (message "Encrypting message '%s'" msg)
    (setq encrypted (sodium-box-encrypt bob-pk eve-sk nonce msg))
    (message "Decrypt message '%s'" encrypted)
    (setq decrypted (sodium-box-decrypt eve-pk bob-sk nonce encrypted))
    (message "Decrypted message '%s'" decrypted))
```

## Thanks
Some C code to work with libsodium was taken from/inspired by
https://github.com/mwarning/libsodium-example

Emacs module code was taken from/inspired by:
- https://phst.eu/emacs-modules
- https://github.com/skeeto/joymacs
- Looking at module code from https://github.com/syohex
- http://diobla.info/blog-archive/modules-tut.html
- https://github.com/jkitchin/emacs-modules

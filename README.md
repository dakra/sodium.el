# Emacs bindings for libsodium

This module is in alpha, works only in Linux with Emacs 25+
and only exposes a high level interface to the
[crypto_box API](https://libsodium.gitbook.io/doc/public-key_cryptography/authenticated_encryption).

## Usage
You can see `sodium-box-demo.el` for a simple example:
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
    (setq encrypted (sodium-box-easy msg nonce bob-pk alice-sk))
    (message "Decrypt message '%s'" encrypted)
    (setq decrypted (sodium-box-open-easy encrypted nonce alice-pk bob-sk))
    (message "Decrypted message '%s'" decrypted))
```

## Thanks
@jedisct1 for [libsodium](https://github.com/jedisct1/libsodium)

Emacs module code was taken from/inspired by:
- https://phst.eu/emacs-modules
- https://github.com/skeeto/joymacs
- Looking at module code from https://github.com/syohex
- http://diobla.info/blog-archive/modules-tut.html
- https://github.com/jkitchin/emacs-modules

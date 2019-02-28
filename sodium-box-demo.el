;;; sodium-box-demo.el --- sodium box demo -*- lexical-binding: t; -*-

;; This is free and unencumbered software released into the public domain.

;;; Commentary:

;; Simple demonstration of the crypto_box API

;;; Code:

(require 'sodium)

(defun sodium-box-demo ()
  "Simple demonstration of the crypto_box API."
  (pop-to-buffer (messages-buffer))
  (let* ((nonce  (sodium-box-make-nonce))
         (bob    (sodium-box-keypair))
         (bob-pk (cdr (assoc 'pk bob)))
         (bob-sk (cdr (assoc 'sk bob)))
         (alice    (sodium-box-keypair))
         (alice-pk (cdr (assoc 'pk alice)))
         (alice-sk (cdr (assoc 'sk alice)))
         (msg "Hello World!")
         encrypted decrypted)
    (message "Encrypting message: '%s'" msg)
    (setq encrypted (sodium-box msg nonce bob-pk alice-sk))
    (message "Decrypt message:    '%s'" encrypted)
    (setq decrypted (sodium-box-open encrypted nonce alice-pk bob-sk))
    (message "Decrypted message:  '%s'" decrypted)
    (message "Nonce:              '%s'" nonce)
    (message "Incremented nonce:  '%s'" (sodium-increment nonce))))

;;; sodium-box-demo.el ends here

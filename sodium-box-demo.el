;;; sodium-box-demo.el --- sodium box demo -*- lexical-binding: t; -*-

;; This is free and unencumbered software released into the public domain.

;;; Commentary:

;; Simple demonstration of the crypto_box API

;;; Code:

(require 'cl-lib)

;; Don't require dynamic module at byte compile time.
(declare-function sodium-box-make-nonce "sodium" ())
(declare-function sodium-box-make-keypair "sodium" ())
(declare-function sodium-box-encrypt "sodium" (pk sk nonce plain))
(declare-function sodium-box-decrypt "sodium" (pk sk nonce encrypted))
(cl-eval-when (load eval)
  (require 'sodium))

(defun sodium-box-demo ()
  "Simple demonstration of the crypto_box API."
  (pop-to-buffer (messages-buffer))
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
    (message "Decrypted message '%s'" decrypted)))

;;; sodium-box-demo.el ends here
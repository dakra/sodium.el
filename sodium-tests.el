;;; sodium-tests.el --- Tests for sodium.el -*- lexical-binding: t; -*-

;; This is free and unencumbered software released into the public domain.

;;; Commentary:

;; ERT test suite for the libsodium dynamic module.
;; Run with `make test'.

;;; Code:

(require 'ert)
(require 'sodium)

(defun sodium-tests--b64-decode (s)
  "Decode base64 string S to a unibyte string."
  (base64-decode-string s))

(defun sodium-tests--b64-encode (s)
  "Encode string S as base64."
  (base64-encode-string s t))

;;; Keypair

(ert-deftest sodium-tests-keypair-shape ()
  (let-alist (sodium-box-keypair)
    (should (stringp .pk))
    (should (stringp .sk))
    (should (= (length (sodium-tests--b64-decode .pk)) sodium-box-publickeybytes))
    (should (= (length (sodium-tests--b64-decode .sk)) sodium-box-secretkeybytes))))

(ert-deftest sodium-tests-keypairs-differ ()
  (should-not (equal (sodium-box-keypair) (sodium-box-keypair))))

;;; Nonce

(ert-deftest sodium-tests-nonce-length ()
  (should (= (length (sodium-tests--b64-decode (sodium-box-make-nonce)))
             sodium-box-noncebytes)))

(ert-deftest sodium-tests-nonces-differ ()
  (should-not (string-equal (sodium-box-make-nonce) (sodium-box-make-nonce))))

;;; Increment

(ert-deftest sodium-tests-increment-zero ()
  "Incrementing an all-zero nonce yields 1 in little-endian."
  (let* ((zeros (sodium-tests--b64-encode (make-string 24 0)))
         (one (concat (string 1) (make-string 23 0))))
    (should (string-equal (sodium-increment zeros)
                          (sodium-tests--b64-encode one)))))

(ert-deftest sodium-tests-increment-twice ()
  (let* ((zeros (sodium-tests--b64-encode (make-string 24 0)))
         (two (concat (string 2) (make-string 23 0))))
    (should (string-equal (sodium-increment (sodium-increment zeros))
                          (sodium-tests--b64-encode two)))))

(ert-deftest sodium-tests-increment-carry ()
  "Increment carries over into the next (little-endian) byte."
  (let* ((max-byte (concat (unibyte-string 255) (make-string 23 0)))
         (carried (concat (unibyte-string 0 1) (make-string 22 0))))
    (should (string-equal (sodium-increment (sodium-tests--b64-encode max-byte))
                          (sodium-tests--b64-encode carried)))))

(ert-deftest sodium-tests-increment-preserves-length ()
  (let ((nonce (sodium-box-make-nonce)))
    (should (= (length (sodium-tests--b64-decode (sodium-increment nonce)))
               sodium-box-noncebytes))))

(ert-deftest sodium-tests-increment-invalid-base64 ()
  (should-error (sodium-increment "not!!valid") :type 'sodium-error)
  (should-error (sodium-increment "") :type 'sodium-error))

;;; Box roundtrips

(defun sodium-tests--roundtrip (msg)
  "Encrypt and decrypt MSG between two fresh keypairs; return the result."
  (let ((nonce (sodium-box-make-nonce)))
    (let-alist `((alice . ,(sodium-box-keypair))
                 (bob . ,(sodium-box-keypair)))
      (sodium-box-open (sodium-box msg nonce .bob.pk .alice.sk)
                       nonce .alice.pk .bob.sk))))

(ert-deftest sodium-tests-roundtrip-ascii ()
  (should (string-equal (sodium-tests--roundtrip "Hello World!") "Hello World!")))

(ert-deftest sodium-tests-roundtrip-embedded-nul ()
  (let ((msg (concat "a" (string 0) "bc")))
    (should (string-equal (sodium-tests--roundtrip msg) msg))))

(ert-deftest sodium-tests-roundtrip-multibyte ()
  (let ((msg "héllo wörld ☃"))
    (should (string-equal (sodium-tests--roundtrip msg) msg))))

(ert-deftest sodium-tests-roundtrip-empty ()
  (should (string-equal (sodium-tests--roundtrip "") "")))

(ert-deftest sodium-tests-roundtrip-json-like ()
  "Roundtrip a payload shaped like the KeePassXC browser protocol."
  (let ((msg "{\"action\":\"get-logins\",\"url\":\"https://example.com\"}"))
    (should (string-equal (sodium-tests--roundtrip msg) msg))))

;;; Known-answer test

(ert-deftest sodium-tests-known-answer ()
  "Fixed test vector generated with libsodium directly.
Guards against base64, length and argument-order regressions that
roundtrip tests cannot catch (a roundtrip also passes when both
directions are consistently wrong)."
  (let ((sk-alice "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=")
        (pk-alice "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=")
        (sk-bob "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2A=")
        (pk-bob "ZLEBsdC+WocEvQePmJUAH8A+jp+VIvGI3RKNmEbUhGY=")
        (nonce "oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3")
        (msg "sodium.el known-answer test")
        (cipher "R7UY7pFXetxI+ASKl7u1QXW2retI8qnohiEo8Jwv5he8qGQSOzz4wM/6aw=="))
    (should (string-equal (sodium-box msg nonce pk-bob sk-alice) cipher))
    (should (string-equal (sodium-box-open cipher nonce pk-alice sk-bob) msg))))

;;; Error cases

(ert-deftest sodium-tests-open-tampered-cipher ()
  (let ((nonce (sodium-box-make-nonce))
        (msg "attack at dawn"))
    (let-alist `((alice . ,(sodium-box-keypair))
                 (bob . ,(sodium-box-keypair)))
      (let* ((cipher (sodium-box msg nonce .bob.pk .alice.sk))
             (raw (sodium-tests--b64-decode cipher)))
        ;; Flip one bit in the raw ciphertext and re-encode.
        (aset raw 0 (logxor (aref raw 0) 1))
        (should-error (sodium-box-open (sodium-tests--b64-encode raw)
                                       nonce .alice.pk .bob.sk)
                      :type 'sodium-error)))))

(ert-deftest sodium-tests-open-wrong-keys ()
  (let ((nonce (sodium-box-make-nonce)))
    (let-alist `((alice . ,(sodium-box-keypair))
                 (bob . ,(sodium-box-keypair))
                 (eve . ,(sodium-box-keypair)))
      (let ((cipher (sodium-box "secret" nonce .bob.pk .alice.sk)))
        (should-error (sodium-box-open cipher nonce .alice.pk .eve.sk)
                      :type 'sodium-error)))))

(ert-deftest sodium-tests-open-wrong-nonce ()
  (let ((nonce (sodium-box-make-nonce)))
    (let-alist `((alice . ,(sodium-box-keypair))
                 (bob . ,(sodium-box-keypair)))
      (let ((cipher (sodium-box "secret" nonce .bob.pk .alice.sk)))
        (should-error (sodium-box-open cipher (sodium-box-make-nonce)
                                       .alice.pk .bob.sk)
                      :type 'sodium-error)))))

(ert-deftest sodium-tests-box-invalid-inputs ()
  (let-alist (sodium-box-keypair)
    (let ((nonce (sodium-box-make-nonce)))
      ;; Invalid base64 nonce.
      (should-error (sodium-box "msg" "not!!valid" .pk .sk) :type 'sodium-error)
      ;; Wrong-length key (valid base64 of 5 bytes).
      (should-error (sodium-box "msg" nonce (sodium-tests--b64-encode "12345") .sk)
                    :type 'sodium-error)
      (should-error (sodium-box "msg" nonce .pk (sodium-tests--b64-encode "12345"))
                    :type 'sodium-error))))

(ert-deftest sodium-tests-open-invalid-cipher ()
  (let-alist (sodium-box-keypair)
    (let ((nonce (sodium-box-make-nonce)))
      ;; Empty and too-short ciphertexts.
      (should-error (sodium-box-open "" nonce .pk .sk) :type 'sodium-error)
      (should-error (sodium-box-open (sodium-tests--b64-encode "short") nonce .pk .sk)
                    :type 'sodium-error)
      (should-error (sodium-box-open "not!!valid" nonce .pk .sk)
                    :type 'sodium-error))))

;;; Constants

(ert-deftest sodium-tests-constants ()
  (should (= sodium-box-macbytes 16))
  ;; Deprecated alias must keep working.
  (should (= sodium-box-maxbytes sodium-box-macbytes))
  (should (= sodium-box-noncebytes 24))
  (should (= sodium-box-publickeybytes 32))
  (should (= sodium-box-secretkeybytes 32)))

(provide 'sodium-tests)
;;; sodium-tests.el ends here

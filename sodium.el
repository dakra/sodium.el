;;; sodium.el --- Some high level bindings for libsodium -*- lexical-binding: t -*-

;; Copyright (c) 2019 Daniel Kraus <daniel@kraus.my>

;; Author: Daniel Kraus <daniel@kraus.my>
;; URL: https://github.com/dakra/sodium.el
;; Keywords: libsodium, crypto, keepassxc, libs, tools
;; Version: 0.2
;; Package-Requires: ((emacs "28.1"))

;; This file is NOT part of GNU Emacs.

;;; License:

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <http://www.gnu.org/licenses/>.

;;; Commentary:

;; This package provides high level bindings for libsodium.

;;; Code:

(unless module-file-suffix
  (error "Module support not detected, sodium can't work"))

(defconst sodium-module--dir
  (file-name-directory (or load-file-name buffer-file-name
                           (locate-library "sodium")))
  "Directory containing the sodium dynamic module source.")

(defun sodium-module-compile ()
  "Compile the sodium dynamic module."
  (interactive)
  (let ((default-directory sodium-module--dir)
        (buffer (get-buffer-create "*sodium-module-compile*")))
    (message "Compiling the sodium dynamic module...")
    (if (zerop (call-process "make" nil buffer t
                             (concat "sodium-module" module-file-suffix)))
        (message "Compiling the sodium dynamic module...done")
      (pop-to-buffer buffer)
      (error "Compilation of the sodium dynamic module failed"))))

(unless (require 'sodium-module nil t)
  (if (or noninteractive
          (y-or-n-p "The sodium dynamic module is not compiled.  Compile it now? "))
      (progn
        (sodium-module-compile)
        (require 'sodium-module))
    (error "Sodium needs its dynamic module; run `make' in %s"
           sodium-module--dir)))

;; Constants defined by the dynamic module.  Declared here so the
;; byte-compiler knows about them in consuming code.
(defvar sodium-box-macbytes)
(defvar sodium-box-maxbytes)            ; Deprecated alias of `sodium-box-macbytes'.
(defvar sodium-box-noncebytes)
(defvar sodium-box-publickeybytes)
(defvar sodium-box-secretkeybytes)


(provide 'sodium)
;;; sodium.el ends here

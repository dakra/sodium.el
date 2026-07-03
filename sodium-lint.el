;;; sodium-lint.el --- Batch lint driver for sodium.el -*- lexical-binding: t; -*-

;; This is free and unencumbered software released into the public domain.

;;; Commentary:

;; Runs checkdoc and (when installed) package-lint over sodium.el and
;; exits non-zero on any finding.  Used by `make lint'.

;;; Code:

(require 'checkdoc)

(defvar sodium-lint--issues 0)

(defun sodium-lint--checkdoc-report (orig text start end &optional unfixable)
  "Count and print checkdoc issue TEXT at START..END, then call ORIG.
UNFIXABLE is passed through to ORIG."
  (setq sodium-lint--issues (1+ sodium-lint--issues))
  (message "checkdoc: %s:%s: %s"
           (buffer-name) (line-number-at-pos start) text)
  (funcall orig text start end unfixable))

(advice-add 'checkdoc-create-error :around #'sodium-lint--checkdoc-report)

(dolist (file '("sodium.el" "sodium-tests.el"))
  (checkdoc-file file))

(require 'package)
(package-initialize)
(if (require 'package-lint nil t)
    (with-current-buffer (find-file-noselect "sodium.el")
      (pcase-dolist (`(,line ,col ,type ,message) (package-lint-buffer))
        (setq sodium-lint--issues (1+ sodium-lint--issues))
        (message "package-lint: sodium.el:%d:%d: %s: %s" line col type message)))
  (message "package-lint not installed, skipping"))

(if (zerop sodium-lint--issues)
    (message "Lint: clean")
  (message "Lint: %d issue(s)" sodium-lint--issues)
  (kill-emacs 1))

(provide 'sodium-lint)
;;; sodium-lint.el ends here

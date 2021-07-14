;;; Directory Local Variables
;;; For more information see (info "(emacs) Directory Variables")

((c-mode . ((indent-tabs-mode . t)
            (show-trailing-whitespace . t)
            (c-basic-offset . 8)))
 (json-mode . ((js-indent-level 4)))
 (python-mode . ((python-formatter . black)
                 (eval (flycheck-select-checker 'python-pylint))
                 (eval setf flycheck-pylintrc (flycheck-locate-config-file-ancestor-directories ".pylintrc" 'python-pylint))
                 (python-fill-column . 88))))

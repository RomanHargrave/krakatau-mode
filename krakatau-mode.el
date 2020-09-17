;; Major mode for editing Krakatau JVM assembler code
;; (C) 2020 Roman Hargrave <roman@hargrave.info>
;; License: GPLv3

(setq krak-instructions
      '("aaload" "aastore" "aconst_null" "aload" "aload_0"
        "aload_1" "aload_2" "aload_3" "anewarray" "areturn"
        "arraylength" "astore" "astore_0" "astore_1"
        "astore_2" "astore_3" "athrow" "baload" "bastore"
        "bipush" "breakpoint" "caload" "castore" "checkcast"
        "d2f" "d2i" "d2l" "dadd" "daload" "dastore" "dcmpg"
        "dcmpl" "dconst_0" "dconst_1" "ddiv" "dload"
        "dload_0" "dload_1" "dload_2" "dload_3" "dmul"
        "dneg" "drem" "dreturn" "dstore" "dstore_0" "dstore_1"
        "dstore_2" "dstore_3" "dsub" "dup" "dup_x1" "dup_x2"
        "dup2" "dup2_x1" "dup2_x2" "f2d" "f2i" "f2l" "fadd"
        "faload" "fastore" "fcmpg" "fconst_0" "fconst_1"
        "fconst_2" "fconst_3" "fdiv" "fload" "fload_0"
        "fload_1" "fload_2" "fload_3" "fmul" "fneg"
        "frem" "freturn" "fstore" "fstore_1" "fstore_2"
        "fstore_3" "fsub" "getfield" "getstatic"
        "goto" "goto_w" "i2b" "i2c" "i2d" "i2f" "i2l" "i2s"
        "iadd" "iaload" "iand" "iastore" "iconst_m1"
        "iconst_0" "iconst_1" "iconst_2" "iconst_3" "iconst_4"
        "iconst_5" "idiv" "if_acmpeq" "if_acmpne" "if_icmpeq"
        "if_icmpge" "if_icmpgt" "if_icmplt" "if_icmpne" "ifeq"
        "ifge" "ifgt" "ifle" "iflt" "ifne" "ifnonnull" "ifnull"
        "iinc" "iload" "iload_0" "iload_1" "iload_2" "iload_3"
        "impdep1" "impdep2" "imul" "ineg" "instanceof" "invokedynamic"
        "invokeinterface" "invokespecial" "invokestatic" "invokevirtual"
        "ior" "irem" "ireturn" "ishl" "istore" "istore_0" "istore_1"
        "istore_2" "istore_3" "isub" "iushr" "ixor" "jsr" "jsr_w"
        "l2d" "l2f" "l2i" "ladd" "laload" "land" "lastore" "lcmp"
        "lconst_0" "lconst_1" "ldc" "ldc_w" "ldc2_w" "ldiv"
        "lload" "lload_0" "lload_1" "lload_2" "lload_3" "lmul" "lneg"
        "lookupswitch" "lor" "lrem" "lreturn" "lshl" "lshr"
        "lstore" "lstore_0" "lstore_1" "lstore_2" "lstore_3"
        "lsub" "lushr" "lxor" "monitorenter" "monitorexit"
        "multianewarray" "newarray" "nop" "pop" "pop2" "putfield"
        "putstatic" "ret" "return" "saload" "sastore" "sipush"
        "swap" "tableswitch" "wide" "new"))

(setq krak-with-local-idx
      (let ((x-instructions
             '("aload" "astore"
               "dload" "dstore"
               "fload" "fstore"
               "iload" "istore"
               "lload" "lstore"
               "iinc")))
        (concat (regexp-opt x-instructions 'words) " +\\([0-9]+\\)")))

(setq krak-with-bare-type
      (let ((x-instructions '("new" "checkcast" "newarray")))
        (concat (regexp-opt x-instructions 'words) " +\\([^ ]+\\)")))

; Expressions for basic elements
(setq krak-member-name "[^ 0-9][^ ]*")
(setq krak-class-type (concat "L" krak-member-name ";"))
(setq krak-primitives "[CDFIJVZ]")
(setq krak-type-spec
      (concat "\\(?:\\[?\\(?:" krak-primitives "\\|" krak-class-type "\\)\\)"))

(setq krak-font-lock-keywords
      (let* ((x-instructions (regexp-opt krak-instructions 'words))
             (x-keywords     (regexp-opt '("final" "abstract" "static" "super" "default"
                                           "protected" "private" "public"
                                           "Method" "Field") 'words))
             (x-assembler-words (regexp-opt '("append same_extended") 'words)))
        `(
          ;; Comments
          ("\\(?:^\\| +\\);.*$" . font-lock-comment-face)
          ;; Single-quote strings
          ("'\\(?:\\\\'\\|[^']*\\)+'" . font-lock-string-face)
          ;; Directives
          ("\\.end[ a-z]+\\|\\.[a-z]+" . font-lock-preprocessor-face)
          ("\\.code +\\(stack\\) +[0-9]+ +\\(locals\\) +[0-9]+"
           . ((1 font-lock-preprocessor-face) (2 font-lock-preprocessor-face)))
          ;; Method declaration (other rules will hilight the rest)
          ("\\.method.* \\([^ ]+\\) :" . (1 font-lock-function-name-face))
          ;; Member field declaration
          (,(concat "\\.field.* \\(" krak-member-name "\\) +\\(" krak-type-spec "\\)")
           . ((1 font-lock-variable-name-face) (2 font-lock-type-face)))
          ;; Class parent spec
          ("\\.super +\\(.+\\)" . (1 font-lock-type-face))
          ;; Class declaration
          ("\\.class.* \\([^ ]+\\) *$" . (1 font-lock-function-name-face))
          ;; try/catch declaration
          ("\\.catch \\([^ ]+\\) \\(from\\) [^ ]+ \\(to\\) [^ ]+ \\(using\\)"
           . ((1 font-lock-type-face) (2 font-lock-keyword-face) (3 font-lock-keyword-face)
              (4 font-lock-keyword-face)))
          ;; stack layout directives
          ("\\.stack +\\([^ ]+\\)" . (1 font-lock-preprocessor-face))
          ("\\.stack +\\(?:append\\|stack_1\\) +\\(.+\\)" . (1 font-lock-type-face))
          ("^ +\\(locals\\|stack\\)\\(.*\\)"
           . ((1 font-lock-preprocessor-face) (2 font-lock-type-face)))
          ;; Signature specification
          (,(concat "(\\(" krak-type-spec "*\\))\\(" krak-type-spec "\\)")
           . ((1 font-lock-type-face) (2 font-lock-type-face)))
          ;; Class specification
          (,krak-class-type . font-lock-type-face)
          ;; Labels
          ("L[0-9]+:?" . font-lock-variable-name-face)
          ;; Instructions
          (,x-instructions . font-lock-builtin-face)
          ;; Instructions that take a local variable index
          (,krak-with-local-idx . (2 font-lock-variable-name-face))
          ;; New instruction
          (,krak-with-bare-type . (2 font-lock-type-face))
          ;; Instructions that reference a field
          (,(concat "\\(?:get\\|put\\).+ Field \\([^ ]+\\) +\\([^ ]+\\) +\\(" krak-type-spec "\\)")
           . ((1 font-lock-type-face) (2 font-lock-variable-name-face) (3 font-lock-type-face)))
          ;; Instructions that reference a method
          ("invoke.+ Method +\\([^ ]+\\) +\\([^ ]+\\)"
           . ((1 font-lock-type-face) (2 font-lock-function-name-face)))
          ;; Line number table entries
          ("^ *L[0-9]+ +\\([0-9]+\\)" . (1 font-lock-keyword-face))
          ;; LVT entries
          ("^ *\\([0-9]+\\) +\\(is\\) +\\([a-z][^ ]*\\) +\\([^ ]+\\) +\\(from\\) +L[0-9]+ +\\(to\\) +L[0-9]"
           . ((1 font-lock-variable-name-face) (2 font-lock-keyword-face) (3 font-lock-variable-name-face)
              (4 font-lock-type-face) (5 font-lock-keyword-face) (6 font-lock-keyword-face)))
          ;; Other stuff
          (,x-assembler-words . font-lock-preprocessor-face)
          ;; Keywords
          (,x-keywords . font-lock-keyword-face)
          )
        ))

(define-derived-mode krakatau-mode fundamental-mode "Krakatau Mode"
  (setq font-lock-defaults '((krak-font-lock-keywords))))

(provide 'krakatau-mode)

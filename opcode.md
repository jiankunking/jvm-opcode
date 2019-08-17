```
-*- koshu -*-

about /group 'constant

|-- OP  /opcode 0    /mnemonic 'nop
|-- OP  /opcode 1    /mnemonic 'aconst_null
|-- OP  /opcode 2    /mnemonic 'iconst_m1

|-- OP  /opcode 3    /mnemonic 'iconst_0
|-- OP  /opcode 4    /mnemonic 'iconst_1
|-- OP  /opcode 5    /mnemonic 'iconst_2
|-- OP  /opcode 6    /mnemonic 'iconst_3
|-- OP  /opcode 7    /mnemonic 'iconst_4
|-- OP  /opcode 8    /mnemonic 'iconst_5

|-- OP  /opcode 9    /mnemonic 'lconst_0
|-- OP  /opcode 10   /mnemonic 'lconst_1

|-- OP  /opcode 11   /mnemonic 'fconst_0
|-- OP  /opcode 12   /mnemonic 'fconst_1
|-- OP  /opcode 13   /mnemonic 'fconst_2

|-- OP  /opcode 14   /mnemonic 'dconst_0
|-- OP  /opcode 15   /mnemonic 'dconst_1

|-- OP  /opcode 16   /mnemonic 'bipush
|-- OP  /opcode 17   /mnemonic 'sipush
|-- OP  /opcode 18   /mnemonic 'ldc
|-- OP  /opcode 19   /mnemonic 'ldc_w
|-- OP  /opcode 20   /mnemonic 'ldc2_w

about /group 'load

|-- OP  /opcode 21   /mnemonic 'iload
|-- OP  /opcode 22   /mnemonic 'lload
|-- OP  /opcode 23   /mnemonic 'fload
|-- OP  /opcode 24   /mnemonic 'dload
|-- OP  /opcode 25   /mnemonic 'aload

|-- OP  /opcode 26   /mnemonic 'iload_0
|-- OP  /opcode 27   /mnemonic 'iload_1
|-- OP  /opcode 28   /mnemonic 'iload_2
|-- OP  /opcode 29   /mnemonic 'iload_3

|-- OP  /opcode 30   /mnemonic 'lload_0
|-- OP  /opcode 31   /mnemonic 'lload_1
|-- OP  /opcode 32   /mnemonic 'lload_2
|-- OP  /opcode 33   /mnemonic 'lload_3

|-- OP  /opcode 34   /mnemonic 'fload_0
|-- OP  /opcode 35   /mnemonic 'fload_1
|-- OP  /opcode 36   /mnemonic 'fload_2
|-- OP  /opcode 37   /mnemonic 'fload_3

|-- OP  /opcode 38   /mnemonic 'dload_0
|-- OP  /opcode 39   /mnemonic 'dload_1
|-- OP  /opcode 40   /mnemonic 'dload_2
|-- OP  /opcode 41   /mnemonic 'dload_3

|-- OP  /opcode 42   /mnemonic 'aload_0
|-- OP  /opcode 43   /mnemonic 'aload_1
|-- OP  /opcode 44   /mnemonic 'aload_2
|-- OP  /opcode 45   /mnemonic 'aload_3

|-- OP  /opcode 46   /mnemonic 'iaload
|-- OP  /opcode 47   /mnemonic 'laload
|-- OP  /opcode 48   /mnemonic 'faload
|-- OP  /opcode 49   /mnemonic 'daload
|-- OP  /opcode 50   /mnemonic 'aaload
|-- OP  /opcode 51   /mnemonic 'baload
|-- OP  /opcode 52   /mnemonic 'caload
|-- OP  /opcode 53   /mnemonic 'saload

about /group 'store

|-- OP  /opcode 54   /mnemonic 'istore
|-- OP  /opcode 55   /mnemonic 'lstore
|-- OP  /opcode 56   /mnemonic 'fstore
|-- OP  /opcode 57   /mnemonic 'dstore
|-- OP  /opcode 58   /mnemonic 'astore

|-- OP  /opcode 59   /mnemonic 'istore_0
|-- OP  /opcode 60   /mnemonic 'istore_1
|-- OP  /opcode 61   /mnemonic 'istore_2
|-- OP  /opcode 62   /mnemonic 'istore_3

|-- OP  /opcode 63   /mnemonic 'lstore_0
|-- OP  /opcode 64   /mnemonic 'lstore_1
|-- OP  /opcode 65   /mnemonic 'lstore_2
|-- OP  /opcode 66   /mnemonic 'lstore_3

|-- OP  /opcode 67   /mnemonic 'fstore_0
|-- OP  /opcode 68   /mnemonic 'fstore_1
|-- OP  /opcode 69   /mnemonic 'fstore_2
|-- OP  /opcode 70   /mnemonic 'fstore_3

|-- OP  /opcode 71   /mnemonic 'dstore_0
|-- OP  /opcode 72   /mnemonic 'dstore_1
|-- OP  /opcode 73   /mnemonic 'dstore_2
|-- OP  /opcode 74   /mnemonic 'dstore_3

|-- OP  /opcode 75   /mnemonic 'astore_0
|-- OP  /opcode 76   /mnemonic 'astore_1
|-- OP  /opcode 77   /mnemonic 'astore_2
|-- OP  /opcode 78   /mnemonic 'astore_3

|-- OP  /opcode 79   /mnemonic 'iastore
|-- OP  /opcode 80   /mnemonic 'lastore
|-- OP  /opcode 81   /mnemonic 'fastore
|-- OP  /opcode 82   /mnemonic 'dastore
|-- OP  /opcode 83   /mnemonic 'aastore
|-- OP  /opcode 84   /mnemonic 'bastore
|-- OP  /opcode 85   /mnemonic 'castore
|-- OP  /opcode 86   /mnemonic 'sastore

about /group 'stack

|-- OP  /opcode 87   /mnemonic 'pop
|-- OP  /opcode 88   /mnemonic 'pop2

|-- OP  /opcode 89   /mnemonic 'dup
|-- OP  /opcode 90   /mnemonic 'dup_x1
|-- OP  /opcode 91   /mnemonic 'dup_x2

|-- OP  /opcode 92   /mnemonic 'dup2
|-- OP  /opcode 93   /mnemonic 'dup2_x1
|-- OP  /opcode 94   /mnemonic 'dup2_x2

|-- OP  /opcode 95   /mnemonic 'swap

about /group 'math

|-- OP  /opcode 96    /mnemonic 'iadd
|-- OP  /opcode 97    /mnemonic 'ladd
|-- OP  /opcode 98    /mnemonic 'fadd
|-- OP  /opcode 99    /mnemonic 'dadd

|-- OP  /opcode 100   /mnemonic 'isub
|-- OP  /opcode 101   /mnemonic 'lsub
|-- OP  /opcode 102   /mnemonic 'fsub
|-- OP  /opcode 103   /mnemonic 'dsub

|-- OP  /opcode 104   /mnemonic 'imul
|-- OP  /opcode 105   /mnemonic 'lmul
|-- OP  /opcode 106   /mnemonic 'fmul
|-- OP  /opcode 107   /mnemonic 'dmul

|-- OP  /opcode 108   /mnemonic 'idiv
|-- OP  /opcode 109   /mnemonic 'ldiv
|-- OP  /opcode 110   /mnemonic 'fdiv
|-- OP  /opcode 111   /mnemonic 'ddiv

|-- OP  /opcode 112   /mnemonic 'irem
|-- OP  /opcode 113   /mnemonic 'lrem
|-- OP  /opcode 114   /mnemonic 'frem
|-- OP  /opcode 115   /mnemonic 'drem

|-- OP  /opcode 116   /mnemonic 'ineg
|-- OP  /opcode 117   /mnemonic 'lneg
|-- OP  /opcode 118   /mnemonic 'fneg
|-- OP  /opcode 119   /mnemonic 'dneg

|-- OP  /opcode 120   /mnemonic 'ishl
|-- OP  /opcode 121   /mnemonic 'lshl
|-- OP  /opcode 122   /mnemonic 'ishr
|-- OP  /opcode 123   /mnemonic 'lshr
|-- OP  /opcode 124   /mnemonic 'iushr
|-- OP  /opcode 125   /mnemonic 'lushr

|-- OP  /opcode 126   /mnemonic 'iand
|-- OP  /opcode 127   /mnemonic 'land
|-- OP  /opcode 128   /mnemonic 'ior
|-- OP  /opcode 129   /mnemonic 'lor
|-- OP  /opcode 130   /mnemonic 'ixor
|-- OP  /opcode 131   /mnemonic 'lxor
|-- OP  /opcode 132   /mnemonic 'iinc

about /group 'conversion

|-- OP  /opcode 133   /mnemonic 'i2l
|-- OP  /opcode 134   /mnemonic 'i2f
|-- OP  /opcode 135   /mnemonic 'i2d

|-- OP  /opcode 136   /mnemonic 'l2i
|-- OP  /opcode 137   /mnemonic 'l2f
|-- OP  /opcode 138   /mnemonic 'l2d

|-- OP  /opcode 139   /mnemonic 'f2i
|-- OP  /opcode 140   /mnemonic 'f2l
|-- OP  /opcode 141   /mnemonic 'f2d

|-- OP  /opcode 142   /mnemonic 'd2i
|-- OP  /opcode 143   /mnemonic 'd2l
|-- OP  /opcode 144   /mnemonic 'd2f

|-- OP  /opcode 145   /mnemonic 'i2b
|-- OP  /opcode 146   /mnemonic 'i2c
|-- OP  /opcode 147   /mnemonic 'i2s

about /group 'comparison

|-- OP  /opcode 148   /mnemonic 'lcmp
|-- OP  /opcode 149   /mnemonic 'fcmpl
|-- OP  /opcode 150   /mnemonic 'fcmpg
|-- OP  /opcode 151   /mnemonic 'dcmpl
|-- OP  /opcode 152   /mnemonic 'dcmpg

|-- OP  /opcode 153   /mnemonic 'ifeq
|-- OP  /opcode 154   /mnemonic 'ifne
|-- OP  /opcode 155   /mnemonic 'iflt
|-- OP  /opcode 156   /mnemonic 'ifge
|-- OP  /opcode 157   /mnemonic 'ifgt
|-- OP  /opcode 158   /mnemonic 'ifle

|-- OP  /opcode 159   /mnemonic 'if_icmpeq
|-- OP  /opcode 160   /mnemonic 'if_icmpne
|-- OP  /opcode 161   /mnemonic 'if_icmplt
|-- OP  /opcode 162   /mnemonic 'if_icmpge
|-- OP  /opcode 163   /mnemonic 'if_icmpgt
|-- OP  /opcode 164   /mnemonic 'if_icmple
|-- OP  /opcode 165   /mnemonic 'if_acmpeq
|-- OP  /opcode 166   /mnemonic 'if_acmpne

about /group 'control

|-- OP  /opcode 167   /mnemonic 'goto
|-- OP  /opcode 168   /mnemonic 'jsr
|-- OP  /opcode 169   /mnemonic 'ret
|-- OP  /opcode 170   /mnemonic 'tableswitch
|-- OP  /opcode 171   /mnemonic 'lookupswitch

|-- OP  /opcode 172   /mnemonic 'ireturn
|-- OP  /opcode 173   /mnemonic 'lreturn
|-- OP  /opcode 174   /mnemonic 'freturn
|-- OP  /opcode 175   /mnemonic 'dreturn
|-- OP  /opcode 176   /mnemonic 'areturn
|-- OP  /opcode 177   /mnemonic 'return

about /group 'reference

|-- OP  /opcode 178   /mnemonic 'getstatic
|-- OP  /opcode 179   /mnemonic 'putstatic
|-- OP  /opcode 180   /mnemonic 'getfield
|-- OP  /opcode 181   /mnemonic 'putfield

|-- OP  /opcode 182   /mnemonic 'invokevirtual
|-- OP  /opcode 183   /mnemonic 'invokespecial
|-- OP  /opcode 184   /mnemonic 'invokestatic
|-- OP  /opcode 185   /mnemonic 'invokeinterface
|-- OP  /opcode 186   /mnemonic 'invokedynamic

|-- OP  /opcode 187   /mnemonic 'new
|-- OP  /opcode 188   /mnemonic 'newarray
|-- OP  /opcode 189   /mnemonic 'anewarray

|-- OP  /opcode 190   /mnemonic 'arraylength
|-- OP  /opcode 191   /mnemonic 'athrow
|-- OP  /opcode 192   /mnemonic 'checkcast
|-- OP  /opcode 193   /mnemonic 'instanceof
|-- OP  /opcode 194   /mnemonic 'monitorenter
|-- OP  /opcode 195   /mnemonic 'monitorexit

about /group 'extended

|-- OP  /opcode 196   /mnemonic 'wide
|-- OP  /opcode 197   /mnemonic 'multianewarray
|-- OP  /opcode 198   /mnemonic 'ifnull
|-- OP  /opcode 199   /mnemonic 'ifnonnull
|-- OP  /opcode 200   /mnemonic 'goto_w
|-- OP  /opcode 201   /mnemonic 'jsr_w

about /group 'reserved

|-- OP  /opcode 202   /mnemonic 'breakpoint
|-- OP  /opcode 254   /mnemonic 'impdep1
|-- OP  /opcode 255   /mnemonic 'impdep2
```
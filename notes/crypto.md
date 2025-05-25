# Crypto 筆記｜JYC 資安工具書

> 本筆記為密碼學與 CTF 密碼題型攻略手冊，涵蓋加解密基本原理、數學工具、常見演算法（對稱加密、非對稱加密、Hash）、CTF 常見技巧與工具使用，並以 `最詳細 × 最專業 × 最讀得懂` 為原則編寫，適用於實戰學習與競賽備查。

---

## 密碼學是什麼

### 密碼學簡介

#### 定義與應用
- 密碼學（Cryptography）是保護資訊安全的科學，核心目標為：機密性（Confidentiality）、完整性（Integrity）、認證（Authentication）與不可否認性（Non-repudiation）。
- 在 CTF 中，Crypto 題目多半考察數論基礎、加密邏輯與破解技巧，而非背誦演算法原理。

#### 常見 CTF 題目類型
- Base 編碼類：Base64 / Hex / ASCII 編碼
- 雜湊類：MD5、SHA1、SHA256（含碰撞、彩虹表）
- 對稱加密類：XOR、AES、ECB、CBC
- 非對稱加密類：RSA（已知 N e c，還原 m）
- 進階類：LFSR、格基攻擊、Padding Oracle

---

## 基礎數學工具

### 模運算（mod）

#### 觀念與性質
- `a ≡ b (mod n)`：a 與 b 除以 n 後餘數相同
- 常見性質：加法/乘法可模內計算、乘法有分配律

```python
a = (7 * 8) % 5  # 56 ≡ 1 mod 5
```

### 最大公因數（GCD）與擴展歐幾里得

```python
from math import gcd

gcd(12, 18)  # 6
```

#### Extended GCD（擴展版）

```python
def egcd(a, b):
    if b == 0:
        return a, 1, 0
    else:
        g, x, y = egcd(b, a % b)
        return g, y, x - (a // b) * y
```

### 模反元素（Modular Inverse）

```python
def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('No modular inverse')
    return x % m

modinv(3, 11)  # 4，因為 3*4 ≡ 1 mod 11
```

### 快速指數運算

```python
pow(3, 4, 5)  # 81 mod 5 = 1
```

---

## 編碼與雜湊函數

### Base 類編碼（Base64, Base32, Hex）

```python
import base64

s = b'jyc'
b64 = base64.b64encode(s)         # Znlj
origin = base64.b64decode(b64)    # jyc
```

### Hex / ASCII / URL

```python
s = 'jyc'
hexed = s.encode().hex()          # 6a7963
bytes.fromhex(hexed)              # b'jyc'
```

### 雜湊函數（Hash）

```python
import hashlib

msg = b'jyc320'
md5 = hashlib.md5(msg).hexdigest()         # 10進位 32字元
sha256 = hashlib.sha256(msg).hexdigest()
```

#### 碰撞與弱點
- MD5 與 SHA1 已不安全，可能產生碰撞
- 常見攻擊：比對輸出繞過認證（如：`hash("admin") == hash("guest")`）

---

## 對稱加密

### XOR 加密

```python
m = 'jyc'
k = 0x20
c = ''.join([chr(ord(i) ^ k) for i in m])  # 加密
m2 = ''.join([chr(ord(i) ^ k) for i in c]) # 解密
```

#### 常見 CTF 題型
- 單位元組 XOR：透過統計頻率猜密鑰
- 重複 XOR key：猜 key 長度，逐位 XOR

### AES 加密

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = b'0123456789abcdef'
iv = b'0000000000000000'
cipher = AES.new(key, AES.MODE_CBC, iv)
ct = cipher.encrypt(pad(b'jyc_message', AES.block_size))

# 解密
dec = AES.new(key, AES.MODE_CBC, iv)
pt = unpad(dec.decrypt(ct), AES.block_size)
```

### 模式比較

| 模式 | 說明 |
|------|------|
| ECB | 每區塊獨立加密，易產生模式 |
| CBC | 鏈結式加密，有 IV 初始向量 |
| CFB / OFB | 串流加密形式，對錯誤敏感 |
| CTR | 加上 counter，支援並行 |

---

## 非對稱加密：RSA

### RSA 原理與流程

#### 關係式
- `n = p * q`，`e` 為公鑰，`d` 為私鑰
- 加密：`c = m^e mod n`
- 解密：`m = c^d mod n`

### RSA 題型實戰

#### 已知 p, q → 求 d

```python
p, q = 61, 53
n = p * q
e = 17
phi = (p - 1) * (q - 1)
d = modinv(e, phi)
```

#### 常見攻擊手法

| 題型             | 方法                      |
|------------------|---------------------------|
| 已知 p, q        | 計算 φ → 解密             |
| 已知 e, d, n     | 求出 φ → 反推 p, q        |
| 小 e 攻擊        | `m^e < n` → 無 mod         |
| 共模攻擊         | 同 m 不同 e，用數學解密   |
| 公開 d 攻擊      | 反推 φ 與質因數分解       |

#### RSA 工具

- `RsaCtfTool`：自動爆破與解密
- `factordb.com`：質因數查詢

---

## 工具與套件整理

### Python 常用套件

- `pycryptodome`：Crypto 演算法庫
- `pwntools.crypto`：基本函數與轉碼
- `gmpy2`：高效數學運算
- `sage`：數學符號系統（進階）

### Crypto CTF 平台

- [CryptoHack](https://cryptohack.org)
- [Cryptopals](https://cryptopals.com)
- [HackTricks Crypto](https://book.hacktricks.xyz/crypto-and-cracking)

---

## Crypto CTF 題型對照

| 題型          | 技巧                   | 說明 |
|---------------|------------------------|------|
| Base 編碼     | b64, ascii, hex        | 多層轉換 |
| Hash 逆推     | 雜湊碰撞 / 彩虹表查詢  | 解密帳號驗證 |
| XOR 加密      | 頻率分析 / key 推測    | 常用一元組 |
| AES ECB/CBC   | 模式識別、爆破 key     | 解出明文 |
| RSA 基本型    | e/n/p/q/d 換算         | 逆推 φ |
| RSA 高級型    | 共模、小 e、洩漏私鑰   | 分解或代數解 |

---


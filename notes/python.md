# Python 資安應用
## 1. Python 基礎
### 字串
- 資料格式：以單引號或雙引號涵括資料
- 可透過索引值（index)取出字元
  |index $\rightarrow$|0|1|2|
  |-------------------|-|-|-|
  |str|j|y|c|
  |index $\leftarrow$|-3|-2|-1|
#### 字串運算
- `+`：字串連接
- `*`：字串重複輸出
- `[i]`：取出索引值i的字元
- `[start_index:end_index:step]`：截取部分字串（不包含end_index)
- `in`：成員運算子，如 'j' in 'jyc' $\Rightarrow$ True
```python
    s = 'jyc'
    
    a = s + '320' # 'jyc320'
    b = s * 2 # 'jycjyc'
    c = s[2] # 'c'
    d = s[::-1] # 'cyj'
    e = s[:2:] # 'jy'
```
#### 字串方法
- \<str\>.lower()：轉成小寫
- \<str\>.upper()：轉成大寫
- \<str\>.replace(old, new)：以新子字串取代舊子字串
- \<str\>.split([sep])：字串以 sep（預設空白）分割，回傳列表
- \<str\>.strip([chars])：移除字串頭尾的 chars(預設空白）子字元
```python
    a = s.lower()         # 'jyc'
    b = s.upper()         # 'JYC'
    c = s.replace('j', 'J')   # 'Jyc'
    d = s.split('y')      # ['j', 'c']
    e = s.strip('j')      # 'yc'
```

### 列表
- Python 中儲存「有順序的可變資料集合」的資料型別
- 使用中括號 `[]` 建立，可包含不同型別的元素
- 列表中的元素可以重複
- 列表是可變的，可以新增、刪除、修改
- 列表在 CTF、資安中常用於
  - 儲存大量資料（如可能密碼、字元組）
  - 處理輸入資料、解碼後處理
  - 建立自動化腳本中的暫存容器
#### 列表運算
- `+`：合併列表
- `*`：重複列表
- `[i]`：取得索引 i 的元素
- `[start:end:step]`：擷取子列表（不包含 end）
- `in`：成員運算子

```python
    s = ['j', 'y', 'c']

    a = s + ['3', '2', '0']     # ['j', 'y', 'c', '3', '2', '0']
    b = s * 2                   # ['j', 'y', 'c', 'j', 'y', 'c']
    c = s[1]                    # 'y'
    d = s[::-1]                 # ['c', 'y', 'j']
    e = s[:2]                   # ['j', 'y']
    f = 'y' in s                # True
```

#### 列表方法
- \<list\>.append(x)：在清單末端加入元素 x
- \<list\>.insert(i, x)：在索引 i 插入元素 x
- \<list\>.pop([i])：移除索引 i 的元素，預設移除最後一個
- \<list\>.remove(x)：移除第一個出現的元素 x
- \<list\>.index(x)：取得元素 x 第一次出現的索引
- \<list\>.count(x)：計算元素 x 出現的次數
- \<list\>.reverse()：就地反轉清單
- \<list\>.sort()：就地排序清單（可排序字串與數字）
```python
    s.append("3")        # ['j', 'y', 'c', '3']
    s.insert(1, "a")     # ['j', 'a', 'y', 'c', '3']
    s.pop()              # ['j', 'a', 'y', 'c']
    s.remove("a")        # ['j', 'y', 'c']
    i = s.index("y")     # 1
    n = s.count("c")     # 1
    s.reverse()          # ['c', 'y', 'j']
    s.sort()             # ['c', 'j', 'y']
```

### 常用函數
#### 運算相關
- `abs(x)`：絕對值  
- `max(iterable)`：回傳最大值
- `min(iterable)`：回傳最小值  
- `sum(iterable)`：回傳總和  
- `pow(x, y)`：回傳 x 的 y 次方（等同 x**y）  
- `round(x, n)`：將數字四捨五入到小數點第 n 位  

```python
    x = -5
    y = [1, 3, 9, 2]

    a = abs(x)         # 5
    b = max(y)         # 9
    c = min(y)         # 1
    d = sum(y)         # 15
    e = pow(2, 3)      # 8
    f = round(3.14159, 2)  # 3.14
```

#### 字元與 ASCII 編碼處理
- `chr(i)`：將整數轉換成對應的 Unicode 字元（如 ASCII）  
- `ord(c)`：將單一字元轉換為對應的整數值（ASCII 或 Unicode 編碼）

```python
    a = chr(65)      # 'A'
    b = ord('A')     # 65
```

#### 進位轉換與進位整數
- `int(x, base)`：將 base 進位的數字字串轉成十進位整數  
- `hex(x)`：將整數轉換為十六進位字串（字首為 0x）  
- `bin(x)`：將整數轉換為二進位字串（字首為 0b）

```python
    a = int("1010", 2)     # 10（二進位 → 十進位）
    b = int("1f", 16)      # 31（十六進位 → 十進位）
    c = hex(255)           # '0xff'
    d = bin(10)            # '0b1010'
```

#### 其他實用函數
- `map(function, iterable)`：將 function 套用到 iterable 的每個元素上  
- `eval(expression)`：執行一段 Python 表達式字串（謹慎使用）

```python
  # map：將每個數字轉成平方
  nums = [1, 2, 3, 4]
  squares = list(map(lambda x: x**2, nums))  # [1, 4, 9, 16]

  # eval：將字串作為程式執行
  expr = "2 + 3 * (4 - 1)"
  result = eval(expr)     # 11
```

#### 補充說明
- `eval()` 能執行任意 Python 程式碼，**不建議在處理外部輸入時使用**，容易導致資安漏洞
- `map()` 通常與 `lambda` 函數搭配，適合處理清單中的資料轉換
- `int(x, base)` 是解碼題目中常見的處理方式

## 2. Python資安應用
#### 模組與套件的匯入與安裝
- 使用 `import` 匯入 Python 內建或第三方模組
- `from 模組 import 函數`：只引入特定功能
- 第三方模組可使用 pip 安裝
    pip 安裝指令：

```bash
    pip install 模組名稱
```
    
```python
    import math
    import base64
    from hashlib import sha256
```

#### 常用模組
1. base64（編碼與解碼）
  - 功能：進行 base64 編碼與解碼  
  - 常見於 Crypto 題目、資料傳輸處理

  ```python
  import base64

  en = base64.b64encode(b'flag{jyc}').decode()        # 'ZmxhZ3tqeWM='
  de = base64.b64decode(jyc).decode()              # 'flag{jyc}'
  ```

2. hashlib（雜湊運算）
  - 功能：產生 MD5、SHA 雜湊值  
  - 用於比對密碼、驗證檔案完整性

  ```python
  import hashlib

  user = 'jyc_320'
  md5_hash = hashlib.md5(passwd.encode()).hexdigest()
  sha256_hash = hashlib.sha256(passwd.encode()).hexdigest()
  ```

3. requests（Web 自動化）
  - 功能：模擬 GET / POST 請求  
  - 常用於 Web 題登入爆破、自動送出表單

  ```python
  import requests

  url = 'http://example.com/login'
  info = {'username': 'jyc', 'password': '1234'}
  response = requests.post(url, data=info)
  print(response.text)
  ```

4. re（正則表達式）
  - 功能：搜尋字串中特定格式（如 flag{...}）  
  - 適用於檔案掃描、log 分析、輸出擷取

  ```python
  import re

  jyc = 'flag{jyc320}'
  result = re.findall(r'flag\{.*?\}', jyc)
  print(result[0])  # 'flag{jyc320}'
  ```

5. sys（輸入參數處理）
  - 功能：讀取外部輸入參數  
  - 常用於自動化腳本接收 base64 / 解碼字串

  ```python
  import sys

  if len(sys.argv) > 1:
    s = sys.argv[1]
    print('輸入參數為：', s)
```

6. os（系統指令與路徑操作）

  - 功能：取得當前目錄、執行系統指令  
  - 常用於自動化處理檔案與命令行

  ```python
  import os

  o = os.getcwd()
  os.system('ls')
  ```

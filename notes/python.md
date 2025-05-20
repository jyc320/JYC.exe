# Python 資安應用
## 1. Python 基礎
### 字串
- 資料格式：以單引號或雙引號涵括資料
- 可透過索引值（index)取出字元
  |index $\rightarrow$|0|1|2|
  |-------------------|-|-|-|
  |str|j|y|c|
  |index $\leftarrow$|-3|-2|-1|
- 字串運算
  - `+`：字串連接
  - `*`：字串重複輸出
  - `[i]`：取出索引值i的字元
  - `[start_index:end_index:step]`：截取部分字串（不包含end_index)
  - `in`：成員運算子，如 "j" in "jyc" $\Rightarrow$ True
    ```python
    s = "jyc"
    
    a = s + "320" # "jyc320"
    b = s * 2 # "jycjyc"
    c = s[2] # "c"
    d = s[::-1] # "cyj"
    e = s[:2:] # "jy"
    ```
- 字串方法
  - \<str\>.lower()：轉成小寫
  - \<str\>.upper()：轉成大寫
  - \<str\>.replace(old, new)：以新子字串取代舊子字串
  - \<str\>.split([sep])：字串以 sep（預設空白）分割，回傳列表
  - \<str\>.strip([chars])：移除字串頭尾的 chars(預設空白）子字元
    ```python
    a = s.lower()         # "jyc"
    b = s.upper()         # "JYC"
    c = s.replace("j", "J")   # "Jyc"
    d = s.split("y")      # ['j', 'c']
    e = s.strip("j")      # "yc"
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
- 列表運算
  - `+`：合併列表
  - `*`：重複列表
  - `[i]`：取得索引 i 的元素
  - `[start:end:step]`：擷取子列表（不包含 end）
  - `in`：成員運算子

    ```python
    s = ["j", "y", "c"]

    a = s + ["3", "2", "0"]     # ['j', 'y', 'c', '3', '2', '0']
    b = s * 2                   # ['j', 'y', 'c', 'j', 'y', 'c']
    c = s[1]                    # "y"
    d = s[::-1]                 # ['c', 'y', 'j']
    e = s[:2]                   # ['j', 'y']
    f = "y" in s                # True
    ```

- 列表方法
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

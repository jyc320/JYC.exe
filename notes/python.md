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
  - `in`：成員運算子
    ```python
    s = "jyc"
    a = s + "320" #"jyc320"
    b = s * 2 #"jycjyc"
    c = s[2] #"c"
    
    
### 常用函數

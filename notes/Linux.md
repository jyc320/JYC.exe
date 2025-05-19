# Linux 基礎資安技術
## 1. 資料層級結構
![image](https://github.com/user-attachments/assets/446dd4f9-8e0e-410b-bf1b-c8ce13a71d62)
Linux採用階層式檔案系統，所有資料都是從跟目錄'/'開始。
|目錄|說明|
|------|------|
|`/(Root directory)`|所有文件集資料夾的最上層目錄|
|`/usr`|用戶應層級程式(大量工具與套件)|
|`/bin`|基本的指令程式所在，如：'ls', 'cp', 'cat'|
|`/sbin`||系統管理用的二進位檔案所在|
|`/etc`|設定檔所在，如：/etc/psswd|
|`/dev`|裝置檔案所在，如：/dev/sda|
|`/var`|日誌、資料苦等檔案所在，如：`/var/log`|
|`/tmp`|暫存檔案，重啟後會被清除|
|`/home`|使用者的主目錄，如：`/home/jyc`|
|`/boot`|引導程式檔案、核心映像核引導所需的設定檔所在|
|`/proc`|系統狀態與程序資訊|
### 補充觀念：
- 一切皆檔案：在 Linux 中，裝置、程式、資料夾都是檔案
- CTF 中常見的 flag 位置：`/home/*`, `/root`, `/var`, `/tmp`
- 特殊注意事項
  - 檔名及目錄名有大小寫區分
    ![linux1](https://github.com/user-attachments/assets/29e0af1b-db2f-4fb7-ac4f-8e6ed7032dbc)

  - 
    


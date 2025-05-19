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
|`/var`|日誌、資料庫等檔案所在，如：`/var/log`|
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

  - 名稱以.開頭可隱藏檔案
    
    ![linux 2](https://github.com/user-attachments/assets/9b6f44f4-db4e-480c-bd89-1f050504cbc1)

  - tab鍵可補足檔案或目錄名稱
  - 執行檔執行需加上路徑，如：./flag
 
## 2. 基本指令
- <command> --help 或 <command> -h：列出指令的說明(重要)
  ```
  ┌──(jyc㉿EVANGELION-01)-[~]
  └─$ man --help
  Usage: man [OPTION...] [SECTION] PAGE...

    -C, --config-file=FILE     use this user configuration file
    -d, --debug                emit debugging messages
    -D, --default              reset all options to their default values
        --warnings[=WARNINGS]  enable warnings from groff

   Main modes of operation:
    -f, --whatis               equivalent to whatis
    -k, --apropos              equivalent to apropos
    -K, --global-apropos       search for text in all pages
    -l, --local-file           interpret PAGE argument(s) as local filename(s)
    -w, --where, --path, --location
                             print physical location of man page(s)
    -W, --where-cat, --location-cat
                             print physical location of cat file(s)

    -c, --catman               used by catman to reformat out of date cat pages
    -R, --recode=ENCODING      output source page encoded in ENCODING

   Finding manual pages:
    -L, --locale=LOCALE        define the locale for this particular man search
    -m, --systems=SYSTEM       use manual pages from other systems
    -M, --manpath=PATH         set search path for manual pages to PATH

    -S, -s, --sections=LIST    use colon separated section list

    -e, --extension=EXTENSION  limit search to extension type EXTENSION

    -i, --ignore-case          look for pages case-insensitively (default)
    -I, --match-case           look for pages case-sensitively

        --regex                show all pages matching regex
        --wildcard             show all pages matching wildcard

        --names-only           make --regex and --wildcard match page names only,
                             not descriptions

    -a, --all                  find all matching manual pages
    -u, --update               force a cache consistency check

        --no-subpages          don't try subpages, e.g. 'man foo bar' => 'man
                               foo-bar'

   Controlling formatted output:
    -P, --pager=PAGER          use program PAGER to display output
    -r, --prompt=STRING        provide the `less' pager with a prompt

    -7, --ascii                display ASCII translation of certain latin1 chars
    -E, --encoding=ENCODING    use selected output encoding
        --no-hyphenation, --nh turn off hyphenation
        --no-justification,                              --nj   turn off justification
    -p, --preprocessor=STRING  STRING indicates which preprocessors to run:
                               e - [n]eqn, p - pic, t - tbl,
  g - grap, r - refer, v - vgrind

    -t, --troff                use groff to format pages
    -T, --troff-device[=DEVICE]   use groff with selected device

    -H, --html[=BROWSER]       use www-browser or BROWSER to display HTML output
    -X, --gxditview[=RESOLUTION]   use groff and display through gxditview
                               (X11):
                               -X = -TX75, -X100 = -TX100, -X100-12 = -TX100-12
    -Z, --ditroff              use groff and force it to produce ditroff

    -?, --help                 give this help list
        --usage                give a short usage message
    -V, --version              print program version

  Mandatory or optional arguments to long options are also mandatory or optional
  for any corresponding short options.

  Report bugs to cjwatson@debian.org. 
  ```
- man <command>：列出指令使用手冊
  ```
  ┌──(jyc㉿EVANGELION-01)-[~]
  └─$ man ls
  LS(1)                                                                                                          User Commands                                                                                                         LS(1)

  NAME
         ls - list directory contents

  SYNOPSIS
         ls [OPTION]... [FILE]...

  DESCRIPTION
         List information about the FILEs (the current directory by default).  Sort entries alphabetically if none of -cftuvSUX nor --sort is specified.
  
         Mandatory arguments to long options are mandatory for short options too.

         -a, --all
                do not ignore entries starting with .

         -A, --almost-all
                do not list implied . and ..

         --author
                with -l, print the author of each file

         -b, --escape
                print C-style escapes for nongraphic characters

         --block-size=SIZE
                with -l, scale sizes by SIZE when printing them; e.g., '--block-size=M'; see SIZE format below

         -B, --ignore-backups
                do not list implied entries ending with ~

         -c     with -lt: sort by, and show, ctime (time of last change of file status information); with -l: show ctime and sort by name; otherwise: sort by ctime, newest first

         -C     list entries by columns

         --color[=WHEN]
                color the output WHEN; more info below

         -d, --directory
                list directories themselves, not their contents

         -D, --dired
                generate output designed for Emacs' dired mode

         -f     same as -a -U

         -F, --classify[=WHEN]
                append indicator (one of */=>@|) to entries WHEN

         --file-type
                likewise, except do not append '*'

         --format=WORD
                across,horizontal (-x), commas (-m), long (-l), single-column (-1), verbose (-l), vertical (-C)

   Manual page ls(1) line 1 (press h for help or q to quit)
  ```
### 目錄操作相關指令
- ls(list)：列出目錄內容。格式：ls [OPTION]
- cd(change directory)：變更當前目錄。格式：cd <dir>
- mkdir(make directory)：在當前目錄下賤粒子目錄。格式：mkdir <dir>
- pwd(prrint working directory)：顯示當前目錄路徑
  ```
  ┌──(jyc㉿EVANGELION-01)-[~]
  └─$ cd ~/My-Security-Growth-Record 
                                                                                                                                                                                                                                           
  ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
  └─$ ls    
    flag  FLAG  notes  README.md
                                                                                                                                                                                                                                           
  ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
  └─$ ls -a 
  .  ..  .flag  flag  FLAG  .git  notes  README.md
                                                                                                                                                                                                                                           
  ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
  └─$ ls -al
  total 32
  drwxrwxr-x  4 jyc jyc 4096 May 19 20:13 .
  drwx------ 55 jyc jyc 4096 May 19 18:25 ..
  -rw-rw-r--  1 jyc jyc   22 May 19 20:12 .flag
  -rw-rw-r--  1 jyc jyc    5 May 19 20:13 flag
  -rw-rw-r--  1 jyc jyc    5 May 19 20:13 FLAG
  drwxrwxr-x  8 jyc jyc 4096 May 19 18:14 .git
  drwxrwxr-x  2 jyc jyc 4096 May 19 18:16 notes
  -rw-rw-r--  1 jyc jyc  500 May 19 18:14 README.md
  ```
- cat(concatenate)：輸出文件內容。格式：cat <file>
- file：判斷檔案型態。格式：file <file>
- grep(global regular expression print)：格式：grep [OPTION] <pattern> <file>
  - 常用選項：
    - `-i`：忽略大小寫
    - `-r`：遞迴搜尋目錄
    - `-n`：顯示行號
    - `-v`：反向匹配（顯示不符合的行）
- more：分頁顯示檔案內容（可滾動閱讀)。格式：more <file>
- cp(copy)：複製檔案或目錄。格式：cp [OPTION] <source> <dir>
- rm(remove)：刪除檔案或空目錄。格式：rm [OPTION] <file>
- find：在檔案系統中搜尋檔案。格式：find [path] [expression]
- strings：顯示檔案中可讀的文字（常用於分析二進位檔)，reverse常用。格式：strings <file>
  ```
  ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
  └─$ cat flag     
  flag
                                                                                                                                                                                                                                           
  ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
  └─$ cat .Flag
  cat: .Flag: No such file or directory
                                                                                                                                                                                                                                           
  ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
  └─$ ls       
  flag  FLAG  notes  README.md
                                                                                                                                                                                                                                           
  ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
  └─$ ls -a 
  .  ..  .flag  flag  FLAG  .git  notes  README.md
                                                                                                                                                                                                                                           
  ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
  └─$ cat .flag
  H1pp0{y0u_r3_50_go0d}
                                                                                                                                                                                                                                           
  ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
  └─$ file flag 
  flag: ASCII text
                                                                                                                                                                                                                                           
  ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
  └─$ cat name | grep -i JYC
  James Emma Liam Olivia Noah Ava William Sophia Benjamin Isabella Lucas Mia Henry Amelia Alexander Harper Ethan Evelyn Jacob Abigail Michael Ella Daniel Scarlett Matthew Grace Sebastian Chloe Jack Lily   Owen Aria Samuel Zoey David Penelope Joseph Layla Carter Riley John Nora Wyatt Camila Leo Victoria Isaac Hannah Luke Aurora Julian Stella Gabriel Natalie Anthony Addison Dylan Leah Lincoln Lucy Jaxon   Brooklyn Asher Paisley Christopher Savannah Josiah Audrey Andrew JYC Bella Thomas Skylar Joshua Claire Ezra Elena Hudson Anna Charles Samantha Caleb Genesis Isaiah Caroline Nathan Kennedy Elijah Sadie   Maverick Hailey Nicholas Aaliyah Dominic Autumn Hunter Violet Austin Mila Levi Eva Aaron Naomi Ryan Ruby Adrian Alice
                                                                                                                                                                                                                                           
  ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
  └─$ rm flag                            
                                                                                                                                                                                                                                           
  ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
  └─$ ls   
  FLAG  name  notes  README.md
                                                                                                                                                                                                                                           
  ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
  └─$ find -name .flag  
  ./.flag
                                                                                                                                                                                                                                           
  ┌──(jyc㉿EVANGELION-01)-[~/SCIST/Kazma-Reverse-Engineering-Course/demo-file]
  └─$ strings chosen0 | grep NCKU
  NCKUCTF{_________________}
  ```
### 檔案存取權限  
![0a942266-4343-4fa1-8040-2f04adc014a9](https://github.com/user-attachments/assets/971d7f2d-0063-4155-b146-09c03993110a)
-chmod(change mode)：變更存取權限。格式： chmod <mode> <file>
  ```
  ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
  └─$ ls -l                    
  total 16
  -rw-rw-r-- 1 jyc jyc    5 May 19 20:13 FLAG
  -rw-rw-r-- 1 jyc jyc  720 May 19 21:11 name
  drwxrwxr-x 2 jyc jyc 4096 May 19 18:16 notes
  -rw-rw-r-- 1 jyc jyc  500 May 19 18:14 README.md
                                                                                                                                                                                                                                           
  ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
  └─$ chmod 000 FLAG                                  
                                                                                                                                                                                                                                           
  ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
  └─$ ls -l
  total 16
  ---------- 1 jyc jyc    5 May 19 20:13 FLAG
  -rw-rw-r-- 1 jyc jyc  720 May 19 21:11 name
  drwxrwxr-x 2 jyc jyc 4096 May 19 18:16 notes
  -rw-rw-r-- 1 jyc jyc  500 May 19 18:14 README.md                                                   
  ```
### 📦檔案壓縮與打包
- 壓縮：依演算法降低檔案儲存容量
- 打包：多個檔案或目錄包裹成一大檔案
- gzip：Linux標準檔案壓縮指令(會取代原檔案)。格式：gzip [option] <file>
- tar(tap archive)：打包指令。格式：tar [option] <tar_file> <file>
```
    ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
    └─$ ls
    example.txt
                                                                                                                                                                           
    ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
    └─$ gzip example.txt
                                                                                                                                                                           
    ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
    └─$ ls
    example.txt.gz
                                                                                                                                                                           
    ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
    └─$ gunzip example.txt.gz
                                                                                                                                                                           
    ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
    └─$ ls
    example.txt
                                                                                                                                                                           
    ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
    └─$ ls
    file1.txt  file2.txt
                                                                                                                                                                           
    ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
    └─$ tar -cvf archive.tar file1.txt file2.txt
    file1.txt
    file2.txt
                                                                                                                                                                           
    ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
    └─$ ls
    archive.tar  file1.txt  file2.txt
                                                                                                                                                                           
    ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
    └─$ tar -czvf archive.tar.gz file1.txt file2.txt
    file1.txt
    file2.txt
                                                                                                                                                                           
    ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
    └─$ ls
    archive.tar.gz  file1.txt  file2.txt
                                                                                                                                                                           
    ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
    └─$ tar -xvf archive.tar
    file1.txt
    file2.txt
                                                                                                                                                                           
    ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
    └─$ tar -xzvf archive.tar.gz
    file1.txt
    file2.txt
```
###常見運算子
- `>`：標準輸出導向（overwrite 覆蓋）
將指令的輸出結果寫入檔案中，會覆蓋檔案原有內容。
- `>>`：標準輸出導向（append 附加)將輸出結果附加到檔案末尾，不會清除原本內容。
- `<`：標準輸入導向（input redirection）將檔案的內容導入某個指令作為輸入。
- `|`：管線（pipe）
將前一個指令的「輸出」直接作為後一個指令的「輸入」。

```
    ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
    └─$ echo "Hello World" > output.txt
                                                                                                                                                                           
    ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
    └─$ echo "Next Line" >> output.txt
                                                                                                                                                                           
    ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
    └─$ wc -l < output.txt
                                                                                                                                                                           
    ┌──(jyc㉿EVANGELION-01)-[~/My-Security-Growth-Record]
    └─$ cat output.txt | grep Hello
```
### 網路相關
1. 本機網路
  - hostname：查看本機名稱
  - ip：查看本機網路介面設定
  - netstat：顯示本機網路連線資訊
2. 查詢遠端主機
  - ping：查看遠端主機連線。格式：ping <ip/dn>
  - traceroute：查看連線路徑。格式：traceroute <ip/dn>
  - nsloop：透過DNS查詢。格式：nslookup <ip/dn>
3. 遠端主機連線
  - ssh(secure shell)：安全加密連線。格式：ssh <usr>@<ip> -p <port>
  - wget(world wide web get)：依url下載檔案。格式：wget <url>
  - nc(netcat)：遠端主機連線(明文傳送)。格式：nc <ip> <port>
  - curl(command-line url)：在command 環境下連接url。格式：curl [options] <url>

## 2. 隱寫術（Steganography）筆記

定義：將資訊「隱藏」在其他檔案（如圖片、音訊、影片等）中，達到不易被察覺的資訊傳遞。
### 🔍 常見藏匿媒介與技巧

| 媒介類型 | 隱藏方式 |
|----------|----------|
| 圖片     | LSB（最低有效位元）嵌入、Exif 資料、附加資料 |
| 音訊     | 波形資料嵌入、ID3 標籤藏訊息 |
| 文件     | 看不見的字元（Unicode Zero-width） |
| 壓縮檔   | 多餘檔案、資料段混入 |

### 🧰 常用工具

| 工具        | 功能說明                     |
|-------------|------------------------------|
| `binwalk`   | 分析檔案結構、提取隱藏內容   |
| `steghide`  | 藏訊息於圖片、音訊中         |
| `zsteg`     | 專門針對 PNG 隱寫分析        |
| `strings`   | 提取檔案中的可讀字串         |
| `exiftool`  | 查看與編輯圖片的 Metadata     |
| `stegsolve` | GUI 工具，可調整圖層觀察異常 |

###### ※好用的線上工具[aprei solve](https://www.aperisolve.com/)

## 3. 數位鑑識

定義：數位鑑識是從電腦、手機、記憶體與網路設備中提取與分析資料的技術，常見於資安事件調查、刑事取證與CTF題目。

### 🖥️ 電腦鑑識
分析電腦硬碟中的檔案系統、刪除資料與磁碟映像，找出潛藏證據。

- 常見操作：
  - 建立磁碟映像檔
  - 還原刪除檔案
  - 探索檔案系統
 
### 🧠 記憶體鑑識
針對電腦 RAM 中的暫存資料進行分析，包含帳號密碼、惡意程式與執行記錄。

- 工具推薦：`volatility`, `strings`, `rekall`
- 常見用途：
  - 抓出執行中的惡意程式
  - 從 RAM 找回明文密碼或 session token

### 🌐 網路鑑識（CTF較著重)
針對封包、流量紀錄、連線紀錄進行分析，追蹤資安事件的來源與影響。

- 工具推薦：`tcpdump`, `tshark`, `NetworkMiner`
- 分析項目：
  - 封包擷取與過濾
  - 抓出傳輸內容（如帳號密碼）
  - 找出可疑連線與IP位置
 
### 🦈 工具介紹-Wireshark  
| 分類         | 說明                                                                 |
|--------------|----------------------------------------------------------------------|
| 軟體名稱     | Wireshark                                                            |
| 類型         | 網路封包分析器（Network Protocol Analyzer）                        |
| 介面         | 圖形化介面 + 支援 CLI (`tshark`)                                    |
| 適用平台     | Windows / Linux / macOS                                              |
| 主要用途     | 擷取、檢視、過濾、重組與分析網路封包                                |
| 支援協定     | 支援超過1000種協定（HTTP, TCP, UDP, DNS, FTP, TLS, etc.）           |
| 常見操作     | - 擷取封包<br>- 過濾協定<br>- 追蹤TCP流（Follow TCP Stream）        |
| 常用過濾器   | - `ip.addr == 192.168.1.1`<br>- `http.request`<br>- `tcp.port == 80` |
| 輸出格式     | .pcap / .pcapng / .txt / .csv                                        |
| 實用功能     | - 標記封包<br>- 追蹤流量<br>- 匯出封包檔案與重建傳輸內容             |
| 搭配工具建議 | `tcpdump`, `tshark`, `NetworkMiner`, `Scapy`                         |

![wireshark](https://github.com/user-attachments/assets/c3f5b789-5097-46c7-9a71-3bf7229eea9f)

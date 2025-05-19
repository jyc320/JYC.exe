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
    


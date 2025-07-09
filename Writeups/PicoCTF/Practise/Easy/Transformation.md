## Transformation

![image](https://github.com/user-attachments/assets/423dbe0b-91cf-4a7b-8ef5-c9d2be304649)

### 解題過程

```python
# encode=''.join([chr((ord(flag[i]) << 8) + ord(flag[i + 1])) for i in range(0, len(flag), 2)])

e_flag = open("enc").read()
print(e_flag)

flag = ""
for i in range(0, len(e_flag)):
	c2 = chr(e_flag[i].encode('utf-16be')[0]) # 從字元編碼中提取高 8 位元
	c2 = chr(e_flag[i].encode('utf-16le')[0]) # 從字元編碼中提取低 8 位元

  ＃ 將解出字元放入flag
  flag += c1
	flag += c2
	
print("Flag: " + flag)

```

![image](https://github.com/user-attachments/assets/02659dca-b3bb-4abf-a737-0f7dd06a8662)

flag get!

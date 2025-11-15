## Hidden in plainsight

<img width="962" height="561" alt="imgq" src="https://github.com/user-attachments/assets/29b945d6-dbfc-4fcc-beb9-796349b4c08a" />

### 解題過程

![img](https://github.com/user-attachments/assets/a7bf6e78-518e-4729-9fae-3e05d2984627)

題目提供的圖片

---

#### 利用`exiftool`讀取Metadata

<img width="649" height="545" alt="img" src="https://github.com/user-attachments/assets/ef9697e5-1223-4181-ac4a-6f49a8970b35" />

找到一串base64 編碼過的文字

<img width="401" height="117" alt="img2" src="https://github.com/user-attachments/assets/38d10691-ae75-4169-8722-688fa65a3959" />

兩次解碼得出`steghide`及密碼，應該是須要用到steghide

#### 用`steghide`看有沒有嵌入內容

<img width="421" height="184" alt="img3" src="https://github.com/user-attachments/assets/f7c85e4d-8e95-44c9-a68f-045c9b8c3028" />

確實圖片裡藏了一個.txt檔

#### 將它提取出來
<img width="485" height="87" alt="img4" src="https://github.com/user-attachments/assets/81875e6e-d568-4063-95c3-e7ea25c6952a" /> <br>

<img width="273" height="52" alt="img5" src="https://github.com/user-attachments/assets/b6ba7171-b0c0-4ca5-876b-ed985fe35f1c" />

flag get!

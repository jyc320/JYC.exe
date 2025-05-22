## shiba-shop

![image](https://github.com/user-attachments/assets/fe32ac77-8c00-4067-b061-595e6f56535c)
![image](https://github.com/user-attachments/assets/983b44aa-c36d-4d1c-ac60-d8b27954b7d8)
點開連結,看起來是一個購物頁面，而現在我們的餘額明顯是不夠的

![image](https://github.com/user-attachments/assets/156cef50-d6dc-46c4-b569-ec02582cdffb)
隨便點開一個物品，打開開發者工具可以發現wallet 的值是可以更動的，於是我將他的值改大在按下Buy 測試餘額是否有變化

![image](https://github.com/user-attachments/assets/b3912964-8caf-4494-b671-70ffb9dd1f9d)
回到到主頁，我們的餘額變成了$9999999999999934464，這樣就可以去買FLAG，但沒有點進去的按鈕

我觀察了每個物品的網址，發現
- White Shiba: `https://chall.nckuctf.org:28100/item/5429`
- Evil Shiba: `https://chall.nckuctf.org:28100/item/5431`

可以合理推測FLAG 應該在`https://chall.nckuctf.org:28100/item/5430`

![image](https://github.com/user-attachments/assets/3ebdc9f3-46a7-462c-90a7-eb048d64bac2)
沒錯!進去就可以看到FLAG 的購買頁面，按下購買之後就可以在主頁看到FLAG
![image](https://github.com/user-attachments/assets/acbb7372-034b-44de-9c4b-9176253acc56)

---

## Redirect

![image](https://github.com/user-attachments/assets/c91fdac6-6a89-4b1b-b224-321640107adb)

---

## Cookie

![image](https://github.com/user-attachments/assets/34996d3d-dd10-43b4-9151-828035724c8e)
![image](https://github.com/user-attachments/assets/5136f7bb-2daf-473b-b52e-89ae6d52cedb)

看起來應該是要讓我們改cookie

![image](https://github.com/user-attachments/assets/47422647-2d1d-4a0a-b2c2-9c26e78a8411)

打開Cookie-Editor

![image](https://github.com/user-attachments/assets/4192094a-2bf4-4c0b-9366-852b3cb6f3a8)

將user 的value 改成cookie_monster 再刷新一次網頁

![image](https://github.com/user-attachments/assets/58468a04-5ee1-4daa-8743-8e093eb008fb)

就可以得到FLAG

---



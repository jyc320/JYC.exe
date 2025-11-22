## Cooked Books

<img width="1107" height="332" alt="image" src="https://github.com/user-attachments/assets/08ffeb7e-95b0-4334-ab59-b7c89e172771" />

### 解題過程
題目給了`the numbers they're giving us for the amount of times that our banned book selection is getting borrowed doesn't seem right`的提示

所以我打算將借閱次數提取出來再解碼

```python
data = """
To Kill a Mockingbird,Harper Lee,77,4.26
1984,George Orwell,101,4.2
The Catcher in the Rye,J.D. Salinger,116,3.8
The Handmaid's Tale, Margaret Atwood,97,4.14
Fahrenheit 451,Ray Bradbury,67,3.96
The Bluest Eye,Toni Morrison,84,4.12
Of Mice and Men,John Steinbeck,70,3.89
Animal Farm,George Orwell,123,4.0
Lord of the Flies,William Golding,49,3.7
The Color Purple,Alice Walker,110,4.27
Brave New World,Aldous Huxley,102,3.99
The Perks of Being a Wallflower,Stephen Chbosky,48,4.23
The Absolutely True Diary of a Part-Time Indian,Sherman Alexie,114,4.06
Beloved,Toni Morrison,109,3.96
The Giver,Lois Lowry,52,4.12
The Hate U Give,Angie Thomas,116,4.46
The Kite Runner,Khaled Hosseini,105,4.35
Slaughterhouse-Five,Kurt Vonnegut Jr.,48,4.1
I Know Why the Caged Bird Sings,Maya Angelou,110,4.3
The Great Gatsby,F. Scott Fitzgerald,95,3.93
Looking for Alaska,John Green,49,3.96
The Adventures of Huckleberry Finn,Mark Twain,115,3.83
Speak,Laurie Halse Anderson,95,4.05
Gender Queer: A Memoir,Maia Kobabe,112,4.27
Anne Frank: The Diary of a Young Girl,Anne Frank,48,4.2
Lolita,Vladimir Nabokov,119,3.88
Harry Potter and the Sorcerer's Stone,J.K. Rowling,51,4.47
All Boys Aren't Blue,George M. Johnson,114,4.19
The Hunger Games,Suzanne Collins,125,4.34
""".strip().split('\n')

nums = [chr(int(line.split(",")[-2])) for line in data] #提取借閱數字,用Ascii解碼
print(*nums, sep="") #MetaCTF{1nf0rm4ti0n_1s_p0w3r}
```

flag get!

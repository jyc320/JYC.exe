## Abashed Confessions
<img width="669" height="752" alt="image" src="https://github.com/user-attachments/assets/49ddee52-eabd-47d0-814a-37e338a74bc4" />

### 解題過程
```
Wvzi Hsrmmb Fkzgivv,

Slkv blf'iv szermt z nviib wzb! R'n rm z yrg lu z hgrxpb hrgfzgrlm
zmw xlfow ivzoob fhv blfi svok.

Hl, Hftzikofn Nzib nzwv gsvhv znzarmt givzgh uli gsv luurxv
kzigb, zmw, dvoo, R xlfowm'g ivhrhg. R vmwvw fk vzgrmt zoo lu gsvn!

Mld gsviv'h mlgsrmt ovug uli gsv kzigb, zmw R'n rm z yrg lu z qzn
(mlg fmorpv gsv uroovw wlmfgh szsz). R mvvw gl hlig gsrh lfg yvuliv
Hftzikofn Nzib li Hzmgz urmw lfg, li gsv kzigb'h tlrmt gl yv z 
wrhzhgvi.

Wl blf szev zmb rwvzh li girxph fk blfi hovvev gl svok nv
dsrk fk hlnv mvd givzgh rm grnv? R pmld R xzm xlfmg lm blf gl 
pvvk gsrh yvgdvvm fh.

R vmxibkgvw gsrh nvhhztv drgs zgyzhs, hl slkvufoob nb orggov
hvxivg rh hzuv.

Gszmph z glm uli yvrmt hfxs z tivzg uirvmw. R ldv blf lmv!

Xsvvih,
Yfhsb Vevitivvm

K.H. Gszg xlwv blf dviv zhprmt zylfg gl fmolxp gsv wvevolknvmg nlwv 
uli gsv Nztrxzo Rmufhrlm Nzxsrmv, N2C24 rh 
NvgzXGU{ylgs_givzgh_zmw_nvhhztvh_hglovm}, slkv gszg svokh!
```
看起來是 Caesar cipher，但嘗試過後沒有解出答案
第二次觀察，密文的`NvgzXGU`應該對應到`MetaCTF`，看起來是 [Alphabetical substitution](https://en.wikipedia.org/wiki/Substitution_cipher) 字母一對一互換 

解密出
```
Dear Shinny Upatree,

Hope you're having a merry day! I'm in a bit of a sticky situation
and could really use your help.

So, Sugarplum Mary made these amazing treats for the office
party, and, well, I couldn't resist. I ended up eating all of them!

Now there's nothing left for the party, and I'm in a bit of a jam
(not unlike the filled donuts haha). I need to sort this out before
Sugarplum Mary or Santa find out, or the party's going to be a 
disaster.

Do you have any ideas or tricks up your sleeve to help me
whip up some new treats in time? I know I can count on you to 
keep this between us.

I encrypted this message with atbash, so hopefully my little
secret is safe.

Thanks a ton for being such a great friend. I owe you one!

Cheers,
Bushy Evergreen

P.S. That code you were asking about to unlock the development mode 
for the Magical Infusion Machine, M2X24 is 
MetaCTF{both_treats_and_messages_stolen}, hope that helps!
```

flag get!

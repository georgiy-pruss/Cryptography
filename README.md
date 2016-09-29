# Cryptography

<pre>
RC5.c          — implementation of RC5 in C. Useless because RC5 is patented.  
RC5.py         — implementation of RC5 in Python. Useless because RC5 is patented.  

sha256.c       — implementation of SHA256. Slow. Use mrm256.c instead.

mrm256.c       — based on MurmurHash3 function, fast and secure enough.  
mrm256test.c   — test suite for mrm256.c.  
<b>salsa20.c</b>      — implementation of salsa20 stream cipher.  
salsa20.coffee — the same in CoffeeScript.  
test_mrm256_salsa20.c — used in salsa20.c for self-test of mrm256 and salsa20.  

speck-128-128-32.cpp speck-64-128-27.cpp — C implementation of speck.  
speck64.ijs speck128.ijs — speck for 64 and 128 bits, in J.  
speck64.py speck128.py — speck for 64 and 128 bits, in Python.  
speck128f.py   — example of using speck for file encryption.  

rijncrypt3.py  — Python implementation of AES; used in pw.py.  
pw.py          — password keeper program (I've been using it for many years :)  

pw.htm         — web interface to pw passwords/data.  
encrypt-pw.htm — used for making pw.js -- password file for pw.htm  
pw.js          — file with encrypted passwords/data for pw.htm  
pwt.htm        — web interface to encrypted files (*.aes)  
me.aes         — sample of encrypted file  
AES.htm        — (useful) demo of AES encryption of text messages  
util/...       — utility js files for the web stuff  

aes.py         — also implementation of AES

dhkx.py        — DH key exchange scheme
execdhkx.py    — program for practical keys exchange
</pre>
To get aes.ijs in the J repository...

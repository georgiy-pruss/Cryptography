# Cryptography

<pre>
RC5.c          — implementation of RC5 in C. Useless because RC5 is patented.  
RC5.py         — implementation of RC5 in Python. Useless because RC5 is patented.  

sha256.c       — implementation of SHA256. Slow. Use mrm256.c instead.

mrm256.c       — based on MurmurHash3 function, fast and secure enough.  
mrm256test.c   — test suite for mrm256.c.  
<b>salsa20.c</b>      — implementation of salsa20 stream cipher.  
test_mrm256_salsa20.c — used in salsa20.c for self-test of mrm256 and salsa20.  

rijncrypt3.py  — Python implementation of AES; used in pw.py.  
pw.py          — password keeper program (I use it for many years :)  

pw.htm         — web interface to pw passwords/data  
encrypt-pw.htm — used for making pw.js -- password file for pw.htm  
pw.js          — file with encrypted passwords/data for pw.htm  
pwt.htm        — web interface to encrypted files (*.aes)  
me.aes         — sample of encrypted file  
AES.htm        — (useful) demo of AES encryption of text messages  
util/...       — utility js files for the web stuff  
</pre>
See also aes.ijs in the J repository.  

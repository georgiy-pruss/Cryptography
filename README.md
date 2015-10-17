# Cryptography

RC5.c      -- implementation of RC5 on C. Useless b/c RC5 is patented.  
RC5.py     -- implementation of RC5 on Python. Useless b/c RC5 is patented.  

sha256.c   -- implementation of SHA256. Slow.  

mrm256.c   -- Murmur3 hash function, fast and secure enough to be used instead of SHA256.  
mrm256test.c -- test suite for mrm256.c.  
**salsa20.c**  -- implementation of salsa20 stream cipher.  
test_mrm256_salsa20.c -- used in salsa20.c for self-test of mrm256 and salsa20.  

rijncrypt3.py  -- Python implementation of AES; used in pw.py.  
pw.py          -- password keeper program (I use it for many years :)  

See also aes.ijs in the j repository.  

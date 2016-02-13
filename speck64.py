#!/usr/bin/env python
# SPECK cipher ~ G.Pruss ~ (C) 2016 ~ based on:
# https://github.com/raullenchai/ciphers/blob/master/pyspeck.py

# expand_key( key:int ) -> list # key size 128 bits (16 bytes)
# encrypt/decrypt( exp_key:list, msg:int ) -> int  # block size 64 (8 bytes)

M32 = (1<<32)-1
def L32(x, j): return ((x<<j) | (x>>(32-j))) & M32 # shift left
def R32(x, j): return ((x>>j) | (x<<(32-j))) & M32 # shift right
def A32(x, y): return (x+y) & M32 # add mod 2^32
def S32(x, y): return (x-y) & M32 # sub mod 2^32

def expand_key(key:int)->list: # key: 128 bits
  k = [ key & M32 ]; l = []
  for i in range( 3 ): key >>= 32; l.append( key & M32 )
  for i in range( 26 ):
    x = A32(k[i], R32(l[i],8)) ^ i; y = L32(k[i],3) ^ x; l.append( x ); k.append( y )
  return k # len(k) = 27 - number of rounds

def encrypt(exp_key:list, plaintext:int)->int: # gets/returns 64-bit int (8-byte block)
  L = (plaintext >> 32) & M32; R = plaintext & M32
  for i in range(27):
    L = A32(R32(L,8), R) ^ exp_key[i]; R = L32(R,3) ^ L
  return (L<<32) | R

def decrypt(exp_key:list, ciphertext:int)->int: # gets/returns 64-bit int (8-byte block)
  L = (ciphertext >> 32) & M32; R = ciphertext & M32
  for i in range(27):
    R = R32(R ^ L,3); L = L32(S32(L ^ exp_key[26-i], R), 8)
  return (L<<32) | R

if __name__== '__main__':
  xk = expand_key(0x1b1a1918131211100b0a090803020100)
  assert encrypt(xk,0x3b7265747475432d) == 0x8c6fa548454e028b
  assert decrypt(xk,0x8c6fa548454e028b) == 0x3b7265747475432d
  '''import time; t=int(time.time()); x = (t<<32)|(t^M32)
  for i in range(1000000): y = encrypt(xk,x); assert y>0 and y!=x and decrypt(xk,y)==x; y = x
  print('1000000 encrypts+decrypts: %.0f s' % (time.time()-t)) # 75s'''
  # replacing shift x,j to shift3 x and shift8 x will gain 9% in performance

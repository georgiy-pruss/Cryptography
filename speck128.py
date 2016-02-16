#!/usr/bin/env python
# SPECK cipher ~ G.Pruss ~ (C) 2016 ~ based on:
# https://github.com/raullenchai/ciphers/blob/master/pyspeck.py

# expand_key( keysz:int, key:int ) -> list # key size 16/24/32 bytes (128/192/256 bits)
# encrypt( exp_key:list, pt:int ) -> int  # block size 16 bytes = 128 bits
# decrypt( exp_key:list, ct:int ) -> int  # block size 128 (16 bytes)

M64 = (1<<64)-1
def L64(x, j): return ((x<<j) | (x>>(64-j))) & M64 # shift left
def R64(x, j): return ((x>>j) | (x<<(64-j))) & M64 # shift right
def A64(x, y): return (x+y) & M64 # add mod 2^64
def S64(x, y): return (x-y) & M64 # sub mod 2^64

def expand_key(keysz:int,key:int)->list: # keysz is 16/24/32 for 128/192/256-bit int key
  m = {16:2,24:3,32:4}[keysz] # number of 64-bit words in key: 2/3/4
  k = [ key & M64 ]; l = []
  for i in range(m-1):
    key >>= 64; l.append( key & M64 )
  for i in range( 30+m-1 ):
    x = A64(k[i], R64(l[i],8)) ^ i; l.append( x )
    y = L64(k[i],3) ^ x;            k.append( y )
  return k # len(k) = 32/33/34 = number of rounds

def encrypt(exp_key:list, plaintext:int)->int: # gets/returns 128-bit int (16-byte block)
  T = len(exp_key); assert 32<=T<=34, "expanded key can be 32, 33 or 34 items"
  L = (plaintext >> 64) & M64
  R = plaintext & M64
  for i in range(T):
    L = A64(R64(L,8), R) ^ exp_key[i]
    R = L64(R,3) ^ L
  return (L<<64) | R

def decrypt(exp_key:list, ciphertext:int)->int: # gets/returns 128-bit int (16-byte block)
  T = len(exp_key); assert 32<=T<=34, "expanded key can be 32, 33 or 34 items"
  L = (ciphertext >> 64) & M64
  R = ciphertext & M64
  for i in range(T,0,-1):
    R = R64(R ^ L,3)
    L = L64(S64(L ^ exp_key[i-1], R), 8)
  return (L<<64) | R

if __name__== '__main__':

  xk = expand_key(16,0x0f0e0d0c0b0a09080706050403020100)
  ct = encrypt(xk,0x6c617669757165207469206564616d20)
  assert ct == 0xa65d9851797832657860fedf5c570d18
  assert decrypt(xk,ct) == 0x6c617669757165207469206564616d20

  xk = expand_key(24,0x17161514131211100f0e0d0c0b0a09080706050403020100)
  ct = encrypt(xk,0x726148206665696843206f7420746e65)
  assert ct == 0x1be4cf3a13135566f9bc185de03c1886
  assert decrypt(xk,ct) == 0x726148206665696843206f7420746e65

  xk = expand_key(32,0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100)
  ct = encrypt(xk,0x65736f6874206e49202e72656e6f6f70)
  assert ct == 0x4109010405c0f53e4eeeb48d9c188f43
  assert decrypt(xk,ct) == 0x65736f6874206e49202e72656e6f6f70

  '''import time; t=int(time.time()); x = (t<<32)|(t^0xffffffff); x = (x<<64)|(x^0xa5a5a5a5a5a5)
  for i in range(1000000): y = encrypt(xk,x); assert y>0 and y!=x and decrypt(xk,y)==x; y = x
  print('1000000 encrypts+decrypts: %.0f s' % (time.time()-t)) ''' # 1M: 96s

  #print( (0x6c617669757165207469206564616d20).to_bytes(16,'little') ) # b' made it equival'
  #print( (0x726148206665696843206f7420746e65).to_bytes(16,'little') ) # b'ent to Chief Har'
  #print( (0x65736f6874206e49202e72656e6f6f70).to_bytes(16,'little') ) # b'pooner. In those'

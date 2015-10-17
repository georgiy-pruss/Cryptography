# -*- coding: utf-8 -*-

# https://github.com/tbb/pyRC5/blob/master/RC5.py
# http://habrahabr.ru/post/267295/

class RC5:

  def __init__(self, W, R, key):
    self.W = W # word size: 16, 32, 64
    self.R = R # rounds: 12, 18, anything 0 to 255
    self.T = 2*(R+1) # S table size
    self.W4 = self.W // 4
    self.W8 = self.W // 8
    self.TW = 2 ** self.W # module
    self.MW = self.TW-1   # mask
    self.key = key
    self.b = len(key) # key size: 0 to 2048 bits
    self.__keyAlign()
    self.__keyExtend()
    self.__shuffle()

  def __lshift(self, val, n):
    n %= self.W
    return ((val<<n)&self.MW) | ((val&self.MW)>>(self.W-n))

  def __rshift(self, val, n):
    n %= self.W
    return ((val<<(self.W-n))&self.MW) | ((val&self.MW)>>n)

  def __const(self,W):
    if W == 16:
      return (0xB7E1, 0x9E37)
    if W == 32:
      return (0xB7E15163, 0x9E3779B9)
    if W == 64:
      return (0xB7E151628AED2A6B, 0x9E3779B97F4A7C15)
    raise Exception("wrong word size")

  def __keyAlign(self):
    if self.b % self.W8 != 0: self.key += b'\0'*(self.W8 - self.b % self.W8)
    self.b = len(self.key)
    self.c = self.b // self.W8
    L = [0]*self.c
    for i in range(self.b-1,-1,-1):
      L[i//self.W8] = (L[i//self.W8]<<8) + self.key[i];
    self.L = L

  def __keyExtend(self):
    P, Q = self.__const(self.W)
    self.S = [(P + i*Q) % self.TW for i in range(self.T)]

  def __shuffle(self):
    i, j, A, B = 0, 0, 0, 0
    for k in range(3 * max(self.c, self.T)):
      A = self.S[i] = self.__lshift((self.S[i] + A + B), 3)
      B = self.L[j] = self.__lshift((self.L[j] + A + B), A + B)
      i = (i + 1) % self.T
      j = (j + 1) % self.c

  def encrypt(self, text):
    if len(text) != self.W4:
      text = text.ljust(self.W4, b'\x00')
    A = int.from_bytes(text[:self.W8], byteorder='little')
    B = int.from_bytes(text[self.W8:], byteorder='little')
    A = (A + self.S[0]) % self.TW
    B = (B + self.S[1]) % self.TW
    for i in range(1, self.R+1):
      A = (self.__lshift((A ^ B), B) + self.S[2*i]) % self.TW
      B = (self.__lshift((B ^ A), A) + self.S[2*i + 1]) % self.TW
    return A.to_bytes(self.W8, byteorder='little') + B.to_bytes(self.W8, byteorder='little')

  def decrypt(self, text):
    if len(text) != self.W4:
      raise Exception("wrong cypher block size")
    A = int.from_bytes(text[:self.W8], byteorder='little')
    B = int.from_bytes(text[self.W8:], byteorder='little')
    for i in range(self.R, 0, -1):
      B = A ^ self.__rshift( B - self.S[2*i + 1], A)
      A = B ^ self.__rshift( A - self.S[2*i], B)
    B = (B - self.S[1]) % self.TW
    A = (A - self.S[0]) % self.TW
    return (A.to_bytes(self.W8, byteorder='little') + B.to_bytes(self.W8, byteorder='little'))

  def encrypt_file(self, inpFileName, outFileName):
    with open(inpFileName, 'rb') as inp, open(outFileName, 'wb') as out:
      more_data = True
      while more_data:
        text = inp.read(self.W4)
        d = self.W4 - len(text)
        if d > 0:
          text += bytes( [d]*d )
          more_data = False
        out.write( self.encrypt( text ) )

  def decrypt_file(self, inpFileName, outFileName):
    with open(inpFileName, 'rb') as inp, open(outFileName, 'wb') as out:
      last_blk = b''
      while True:
        text = inp.read(self.W4)
        if len(text)==0:
          n = last_blk[-1]
          out.write( last_blk[:self.W4-n] )
          break
        out.write( last_blk )
        last_blk = self.decrypt( text )

  def encrypt_bytes(self, inp):
    LI = len(inp)
    done = 0
    out = b''
    while done < LI:
      text = inp[done:done + self.W4]
      done += self.W4
      out += self.encrypt( text )
    return out

  def decrypt_bytes(self, inp, lres):
    LI = len(inp)
    done = 0
    out = b''
    while done < LI:
      text = inp[done:done + self.W4]
      done += self.W4
      out += self.decrypt( text )
    return out[:lres]

if __name__=="__main__":
  import sys,os,time
  def b2s(x): return ("%08X %08X" %
    (int.from_bytes(x[:4], byteorder='little'),int.from_bytes(x[4:], byteorder='little')))
  # Sanity test
  rc5 = RC5(32,12,b'\0'*16)
  ct = rc5.encrypt(b'\0'*8)
  assert ct==b"\x21\xA5\xDB\xEE\x15\x4B\x8F\x6D"
  assert rc5.decrypt(ct)==b'\0'*8
  if len(sys.argv)==1 or sys.argv[1]!="--test":
    sys.exit()
  # Official sample
  ct = b'\0'*8
  for i in range(1,6):
    pt = ct
    c0 = int.from_bytes(ct[:4], byteorder='little')
    key = bytes([c0%(255-j) for j in range(16)])
    rc = RC5(32,12,key)
    ct = rc.encrypt( pt )
    rt = rc.decrypt( ct )
    print("\n%d) key =" % i, "%s" % " ".join(["%02X"%b for b in key]) )
    print("   plaintext %s  --->  ciphertext %s" % (b2s(pt),b2s(ct)) )
    if pt!=rt:
      printf("Decryption Error!")
  print()
  # Files
  rc5 = RC5(32,12,b'\0'*16)
  F = sys.argv[0]
  for l in range(260):
    for c in (b'\0',b'\x01',b'\x55',b'\xFF'):
      t0 = c * l
      with open( F+".0", "wb" ) as fo: fo.write( t0 )
      rc5.encrypt_file( F+".0", F+".rc5" )
      rc5.decrypt_file( F+".rc5", F+".1" )
      with open( F+".1", "rb" ) as fi: t1 = fi.read()
      assert t0 == t1
      print( "%02X"%c[0], l, end="\r" )
  t0 = open( F, "rb" ).read()
  rc5.encrypt_file( F, F+".rc5" )
  rc5.decrypt_file( F+".rc5", F+".1" )
  with open( F+".1", "rb" ) as fi: t1 = fi.read()
  assert t0 == t1
  os.unlink( F+".0" )
  os.unlink( F+".1" )
  os.unlink( F+".rc5" )
  # Byte strings
  tc = rc5.encrypt_bytes( b'' )
  t1 = rc5.decrypt_bytes( tc, 0 )
  assert b'' == t1
  rc5 = RC5(32,12,b'\xFF'*64)
  tc = rc5.encrypt_bytes( b'' )
  t1 = rc5.decrypt_bytes( tc, 0 )
  assert b'' == t1
  tc = rc5.encrypt_bytes( t0 )
  t1 = rc5.decrypt_bytes( tc, len(t0) )
  assert t0 == t1
  bts = 0
  spd = 0
  tm0 = time.time()
  for l in range(1,len(t0)):
    if l>1025 and l%10!=0: continue
    if l>2500 and l%100!=0: continue
    print( l, end=" " )
    tc = rc5.encrypt_bytes( t0[:l] )
    t1 = rc5.decrypt_bytes( tc, l )
    bts += l + len(tc)
    assert t0[:l] == t1
    tc = rc5.encrypt_bytes( t0[-l:] )
    t1 = rc5.decrypt_bytes( tc, l )
    bts += len(tc)+l
    assert t0[-l:] == t1
    tm1 = time.time()
    if tm1>tm0: spd = bts/(tm1-tm0)//1000
    print( "%dkB/s" % spd, end="\r" ) # 212kB/s on mine
  print()

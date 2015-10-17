# rijcrypt.py
# Rijndael encryption - used in AES
# 20040711-050737
# Georgy Pruss - d001120t0330@hotmail.com

# Speed with psyco ~145000 B/s (???) HP 18 kB/s, Acer 48 kB/s

# todo: Pack/Unpack, arrays, str-to-byte and back, fix dout += [...]

# ****************************************************************
#
#   MODULE:   pyRijndael
#   FILENAME: pyRijndael.py
#   AUTHOR:   Jeff Clement <jeff@bluesine.com>
#   WEB:      http://www.bluesine.com/archives/software/python-mods/rijndael
#   LICENSE:  http://www.bluesine.com/license
#   VERSION:  $Id: pyRijndael.py 1.1 2001/07/19 07:23:36 JSC Exp JSC $
#
#   DESCRIPTION:
#   A pure-python implementation of the AES Rijndael Block Cipher.
#   Basic on Phil Fresle's VB implementation.  Notice: this has not
#   been verified to correctly implement the Rijndael cipher.  You
#   may want to test it yourself before using in a hostile environment.
#
# ****************************************************************

# http://fp.gladman.plus.com/cryptography_technology/rijndael/
# http://www.esat.kuleuven.ac.be/~rijmen/rijndael/ [1]
# http://home.ecn.ab.ca/~jsavard/crypto/co040401.htm
# http://rijndael.com/
# Animation: [1]/Rijndael_Anim_swf.zip

# This improves performance 10 times:
try:
  import psyco
  psyco.full()
  #psyco.log('here.log')
  #psyco.profile()
except ImportError:
  pass

# LUTs for Performance
lutLOnBits=[]
lutL2Power=[]
lutBOnBits=[]
lutB2Power=[]

lutInCo   = []
lutRCO    = [0] * 30

lutPTab   = [0] * 256
lutLTab   = [0] * 256
lutFBSub  = [0] * 256
lutRBSub  = [0] * 256
lutFTable = [0] * 256
lutRTable = [0] * 256

def buildLUTs():
  """
  Populate lookup tables with some frequently used values
  """
  lutInCo.append(0xB)
  lutInCo.append(0xD)
  lutInCo.append(0x9)
  lutInCo.append(0xE)

  for i in range(8):
    lutB2Power.append(2**i)
    lutBOnBits.append(sum(lutB2Power))

  for i in range(31):
    lutL2Power.append(2**i)
    lutLOnBits.append(sum(lutL2Power))

def LShiftL(lValue, iShiftBits): # Unsigned 32-bit left-shift
  #assert iShiftBits in (8,16,24)
  if iShiftBits == 8:
    if lValue & 0x00800000:
      return ((lValue & 0x007fffff) << 8) | 0x80000000
    return (lValue & 0x00ffffff) << 8
  if iShiftBits == 16:
    if lValue & 0x00008000:
      return ((lValue & 0x00007fff) << 16) | 0x80000000
    return (lValue & 0x0000ffff) << 16
  # assert iShiftBits == 24
  if lValue & 0x00000080:
    return ((lValue & 0x0000007F) << 24) | 0x80000000
  return (lValue & 0x000000FF) << 24

def RShiftL(lValue, iShiftBits): # Unsigned 32-bit right-shift
  #assert iShiftBits in (8,16,24)
  if lValue & 0x80000000:
    return ((lValue & 0x7FFFFFFF) >> iShiftBits) | (0x40000000 >> (iShiftBits-1))
  return lValue >> iShiftBits

def LShiftB(bValue, iShiftBits): # Unsigned 8-bit left-shift
  return (bValue << iShiftBits) & 0xFF

def RShiftB(bValue, iShiftBits): # Unsigned 8-bit right-shift
  return bValue >> iShiftBits

def RotateLeftL(lValue, iShiftBits):
  #assert iShiftBits in (8,16,24)
  return LShiftL(lValue, iShiftBits) | RShiftL(lValue, (32-iShiftBits))

def RotateLeftB(bValue, iShiftBits):
  return ((bValue << iShiftBits) & 0xFF) | (bValue >> (8-iShiftBits))

def Pack( b ):
  return b[0] | (b[1] << 8) | (b[2] << 16) | LShiftL( b[3], 24 )

def Unpack( a, b ):
  b[0] = (a    ) & 0xFF
  b[1] = (a>> 8) & 0xFF
  b[2] = (a>>16) & 0xFF
  b[3] = (a>>24) & 0xFF

def PackSlice( b, k ):
  return b[k] | (b[k+1] << 8) | (b[k+2] << 16) | LShiftL( b[k+3], 24 )

def UnpackSlice( a, b, k ):
  b[k  ] = (a    ) & 0xFF
  b[k+1] = (a>> 8) & 0xFF
  b[k+2] = (a>>16) & 0xFF
  b[k+3] = (a>>24) & 0xFF

def SubByte(a):
  b=[0] * 4
  Unpack(a,b)
  for i in range(4):
    b[i] = lutFBSub[b[i]]
  return Pack(b)

def xtime(a):
  if a & 0x80:
    return LShiftB(a,1) ^ 0x1B
  return LShiftB(a,1)

def bmul(x, y):
  if x==0 or y==0:
    return 0
  return lutPTab[ (int(lutLTab[x]) + int(lutLTab[y])) % 255 ]

def product(x,y):
  xb=[0]*4
  yb=[0]*4
  Unpack(x, xb)
  Unpack(y, yb)
  return bmul(xb[0], yb[0]) ^ bmul(xb[1], yb[1]) ^ \
          bmul(xb[2], yb[2]) ^ bmul(xb[3], yb[3])

def InvMixCol(x):
  b=[0,0,0,0]
  m=Pack(lutInCo)
  b[3]=product(m,x)
  m = RotateLeftL(m, 24)
  b[2]=product(m,x)
  m = RotateLeftL(m, 24)
  b[1]=product(m,x)
  m = RotateLeftL(m, 24)
  b[0]=product(m,x)
  return Pack(b)

def genTables():
  """
  Generate a bunch of lookup tables needed
  """

  def ByteSub(x):
    y = lutPTab[255 - lutLTab[x]]
    x = y
    x = RotateLeftB(x,1)
    y ^= x
    x = RotateLeftB(x,1)
    y ^= x
    x = RotateLeftB(x,1)
    y ^= x
    x = RotateLeftB(x,1)
    y ^= x
    return y ^ 0x63

  lutLTab[0]=0
  lutPTab[0]=1
  lutLTab[1]=0
  lutPTab[1]=3
  lutLTab[3]=1

  for i in range(2,256):
    lutPTab[i] = lutPTab[i-1] ^ xtime(lutPTab[i-1])
    lutLTab[lutPTab[i]]=i

  lutFBSub[0]=0x63
  lutRBSub[0x63]=0

  for i in range(1,256):
    y = ByteSub(i)
    lutFBSub[i]=y
    lutRBSub[y]=i

  y=1
  for i in range(30):
    lutRCO[i]=y
    y=xtime(y)

  b=[0,0,0,0]
  y=0
  for i in range(256):
    y=lutFBSub[i]
    b[3] = y ^ xtime(y)
    b[2] = y
    b[1] = y
    b[0] = xtime(y)
    lutFTable[i] = Pack(b)

    y=lutRBSub[i]
    b[3]=bmul(lutInCo[0],y)
    b[2]=bmul(lutInCo[1],y)
    b[1]=bmul(lutInCo[2],y)
    b[0]=bmul(lutInCo[3],y)
    lutRTable[i] = Pack(b)

class RijndaelCrypt:

  def __init__( self ):
    self.Nb = 0
    self.Nk = 0
    self.Nr = 0
    self.fi = [0]*24
    self.ri = [0]*24
    self.fkey = [0]*120 # 4*30
    self.rkey = [0]*120 # 4*30

  def gkey( self, nb, nk, key ):
    i=0
    j=0
    k=0
    m=0
    N=0
    C1=0
    C2=0
    C3=0
    CipherKey=[0] * 8

    self.Nb=nb # bytes in block
    self.Nk=nk # bytes in key

    if self.Nb >= self.Nk:
      self.Nr = 6 + self.Nb
    else:
      self.Nr = 6 + self.Nk

    C1=1
    if self.Nb < 8:
      C2=2
      C3=3
    else:
      C2=3
      C3=4

    for j in range(nb):
      m = j * 3
      self.fi[m+0] = (j+C1) % nb
      self.fi[m+1] = (j+C2) % nb
      self.fi[m+2] = (j+C3) % nb
      self.ri[m+0] = (nb+j-C1) % nb
      self.ri[m+1] = (nb+j-C2) % nb
      self.ri[m+2] = (nb+j-C3) % nb

    N = self.Nb * (self.Nr+1)

    for i in range(self.Nk):
      CipherKey[i] = PackSlice(key,i*4)

    for i in range(self.Nk):
      self.fkey[i] = CipherKey[i]

    j = self.Nk
    k = 0

    while j < N:
      self.fkey[j] = self.fkey[j-self.Nk] ^ \
                     SubByte(RotateLeftL(self.fkey[j-1],24)) ^ lutRCO[k]
      if self.Nk <= 6:
        i=1
        while i < self.Nk and (i+j) < N:
          self.fkey[i+j] = self.fkey[i+j-self.Nk] ^ self.fkey[i+j-1]
          i += 1
      else:
        i=1
        while i < 4 and (i+j) < N:
          self.fkey[i+j] = self.fkey[i+j-self.Nk] ^ self.fkey[i+j-1]
          i += 1
        if j + 4 < N:
          self.fkey[j+4] = self.fkey[j+4-self.Nk] ^ SubByte(self.fkey[j+3])
        i=5
        while i < self.Nk and (i+j) < N:
          self.fkey[i+j] = self.fkey[i+j-self.Nk] ^ self.fkey[i+j-1]
          i += 1
      j += self.Nk
      k += 1

    for j in range(self.Nb):
      self.rkey[j+N-nb]=self.fkey[j]

    i=self.Nb

    while i < N - self.Nb:
      k=N-self.Nb-i
      for j in range(self.Nb):
        self.rkey[k+j] = InvMixCol(self.fkey[i+j])
      i += self.Nb

    j=N-self.Nb
    while j < N:
      self.rkey[j-N+self.Nb] = self.fkey[j]
      j += 1

  def Encrypt( self, buff ):
    a=[0]*8
    b=[0]*8
    tmp = list(buff)
    for i in range(self.Nb):
      j=i*4
      a[i] = PackSlice(tmp,j)
      a[i] ^= self.fkey[i]
    k=self.Nb
    x=a
    y=b

    RLL = RotateLeftL
    SHR = RShiftL
    LOB = lutLOnBits

    for i in range(1,self.Nr):
      for j in range(self.Nb):
        m=j*3
        y[j] = self.fkey[k] ^ \
          lutFTable[x[j] & LOB[7]] ^ \
          RLL(lutFTable[SHR(x[self.fi[m    ]],  8) & LOB[7]], 8) ^ \
          RLL(lutFTable[SHR(x[self.fi[m + 1]], 16) & LOB[7]], 16) ^ \
          RLL(lutFTable[SHR(x[self.fi[m + 2]], 24) & LOB[7]], 24)
        k += 1
      t = x
      x = y
      y = t

    for j in range(self.Nb):
      m=j*3
      y[j] = self.fkey[k] ^ lutFBSub[x[j] & LOB[7]] ^ \
        RLL(lutFBSub[SHR(x[self.fi[m    ]],  8) & LOB[7]], 8) ^ \
        RLL(lutFBSub[SHR(x[self.fi[m + 1]], 16) & LOB[7]], 16) ^ \
        RLL(lutFBSub[SHR(x[self.fi[m + 2]], 24) & LOB[7]], 24)
      k += 1

    for i in range(self.Nb):
      j=i*4
      UnpackSlice( y[i], tmp, j )
      x[i]=0
      y[i]=0

    return tmp

  def Decrypt( self, buff ):
    a=[0]*8
    b=[0]*8
    tmp = list(buff)

    for i in range(self.Nb):
      a[i] = PackSlice(tmp, i*4) ^ self.rkey[i]

    k=self.Nb
    x=a
    y=b

    RLL = RotateLeftL
    SHR = RShiftL
    LOB = lutLOnBits

    for i in range(1,self.Nr):
      for j in range(self.Nb):
        m=j*3
        y[j]=self.rkey[k] ^ lutRTable[x[j] & LOB[7]] ^ \
             RLL(lutRTable[SHR(x[self.ri[m  ]], 8) & LOB[7]], 8) ^ \
             RLL(lutRTable[SHR(x[self.ri[m+1]],16) & LOB[7]],16) ^ \
             RLL(lutRTable[SHR(x[self.ri[m+2]],24) & LOB[7]],24)
        k += 1
      t=x
      x=y
      y=t

    for j in range(self.Nb):
      m=j*3
      y[j]=self.rkey[k] ^ lutRBSub[x[j] & LOB[7]] ^ \
           RLL(lutRBSub[SHR(x[self.ri[m  ]], 8) & LOB[7]], 8) ^ \
           RLL(lutRBSub[SHR(x[self.ri[m+1]],16) & LOB[7]],16) ^ \
           RLL(lutRBSub[SHR(x[self.ri[m+2]],24) & LOB[7]],24)
      k += 1

    for i in range(self.Nb):
      j=i*4
      UnpackSlice(y[i],tmp,j)
      x[i]=0
      y[i]=0

    return tmp

# #########################
# DATA PROCESSING FUNCTIONS
# #########################

class CryptError(Exception):
  pass

def padModulus(arr):
  if (len(arr) % 32) == 0:
    return arr
  return arr + [0]*(32-len(arr) % 32)

def EncryptData( key, data ):
  """
  Usage: EncryptData(key, data)
    key(bytes): password for encryption
    data(bytes): data for encryption

  Encrypts data using key and returns encrypted string (bytes).
  Uses 256 bit Rijndael cipher.
  Key is 32 bytes.
  A 4-byte message length is attached to beginning of ciphertext.
  """
  # add 32 bit number for length
  r = RijndaelCrypt()
  r.gkey( 8, 8, list(key) )

  sz = [0]*4
  Unpack( len(data), sz )
  din = padModulus( sz + list(data) )
  dout=[]
  for ofs in range( 0, len(din), 32 ): # operate on 32bit blocks
    dout += r.Encrypt( [int(_) for _ in din[ofs:ofs+32]] )
  return bytes(dout)

def DecryptData( key, data ):
  """
  Usage: DecryptData(key, data)
    key(bytes): password for decryption (32 bytes)
    data(bytes): data for decryption
  returns bytes
  """
  r = RijndaelCrypt()
  r.gkey( 8, 8, list(key) )
  din = list(data)
  dout = []
  for ofs in range( 0, len(din), 32 ): # operate on 32bit blocks
    dout += r.Decrypt( din[ofs:ofs+32] )
  sz = Pack( dout )     # extract size information
  if 0 <= len(dout)-4-sz < 32:
    dout = dout[4:4+sz]   # remove size data
  else:
    raise CryptError("Wrong data or password")
  return bytes( dout )

buildLUTs()
genTables()
#for i,p in enumerate(lutL2Power): print i,hex(p),hex(lutLOnBits[i])

import hashlib

def md5_digest( data ):
  m = hashlib.md5()
  m.update( data )
  return m.digest()

def make_key( pwd ):
  lpwd = (len(pwd) & 0x7F) + 0x20
  key = bytes([lpwd]) + pwd
  aux = md5_digest( key ) + md5_digest( pwd ) # additional 32 bytes
  value = 0
  for kd in key:
    if not (0x20 <= kd <= 0x7E):
      return None
    value = (value * 0x60) + (kd-0x1F)
  ret = [0]*32
  for i in range(32):
    if value > 0:
      value, rem = divmod( value, 0x100 )
      ret[i] = int(rem)
    else:
      ret[i] = aux[i]
  return ret


key = make_key("qwerty".encode('utf-8'))
pt  = "hello world".encode('utf-8')
ct  = EncryptData( key, pt )
# a21f0146675c0db803ce0cd484de3c248ee93c66df4b0bd19873d484f1256305
ot = DecryptData( key, ct )
assert( pt == ot )


# ####
# MAIN
# ####

if __name__=='__main__':

  import sys,time

  if len(sys.argv)<4 or sys.argv[1] not in ("e","d"):
    print("rijncrypt.py e|d infile outfile [password]")
    sys.exit(0)

  if len(sys.argv)==5:
    pw = sys.argv[4]
  else:
    pw = input("password: ")
  key = make_key( pw.encode('utf-8') )

  fi = open(sys.argv[2],"rb")
  ti = fi.read()
  fi.close()

  fn = sys.argv[1]=="e" and EncryptData or DecryptData
  try:
    t1 = time.time()
    to = fn( key, ti )
    t2 = time.time()
    te = t2 - t1
    if te==0: te=0.1
    print("%d bytes, %.1f seconds, %.0f bytes/second" % (len(to),te,len(to)/te))
  except CryptError:
    print("Wrong password?")
    sys.exit(0)

  fo = open(sys.argv[3],"wb")
  fo.write( to )
  fo.close()

# EOF

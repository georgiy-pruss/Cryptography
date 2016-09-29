# Execute DH key exchange (C) 2016 G.Pruss
# Choose password, then get public key for your password, then
# exchange the public keys with your 2nd party, then you'll have
# your common key for encryption (keep it secret!)
# For more on DHKX, see dhkx.py and follow the links there

import dhkx

def choose_mode() -> int:
  m = (1536, 2048, 3072, 4096, 6144, 8192)
  t = "  1 - 1536, 2 - 2048, 3 - 3072, 4 - 4096, 5 - 6144, 6 - 8192 [default]"
  while "mode entering":
    print( "Choose modulo length:" )
    print( t )
    k = input( "Enter number: " )
    if len(k)==0: return 8192
    if k in ("1","2","3","4","5", "6"): return m[int(k)-1]
    if k.isdigit() and int(k) in m: return int(k)

def enter_kind() -> int:
  txt = """Choose your key (password) type:
  1 - decimal digits (21+ digits recommended)
  2 - hexadecimal (18+ hex.digits recommended)
  3 - alphanumeric case-insensitive (14)
  4 - alphanumeric case-sensitive (12) [default]
  5 - any printable ASCII (11)"""
  while "password kind entering":
    print( txt )
    k = input( "Enter number: " )
    if len(k)==0: return 4 # default
    if k in ("1","2","3","4","5"): return int(k)

def chk_kind( k: int, p: int ) -> bool:
  if k==1 and p.isdigit(): return True
  if k==2 and p.isalnum():
    for c in p:
      if c not in "0123456789abcdefABCDEF": return False
    return True
  if (k==3 or k==4) and p.isalnum(): return True
  if k==5: return True
  return False

def enter_pwd( k: int ) -> int:
  while "password entering":
    p = input( "Enter password: " )
    if len(p)>0 and not chk_kind( k, p ):
      print( "Bad character" )
      continue
    if len(p)<3: # well, maybe not needed, maybe confirmation...
      print( "Too short" )
      continue
    return p

def parse_36( s: str ) -> int: # 36 = 0..9 A..Z i.e. 10+26
  n = 0
  for c in s.upper():
    if '0'<=c<='9': n=n*36+ord(c)-ord('0')
    elif 'A'<=c<='Z': n=n*36+ord(c)-ord('A')+10
    else: pass # ignore other chars
  return n

def parse_62( s: str ) -> int: # 52 = 0..9 A..Z a..z i.e. 10+26+26
  n = 0
  for c in s:
    if '0'<=c<='9': n=n*62+ord(c)-ord('0')
    elif 'A'<=c<='Z': n=n*62+ord(c)-ord('A')+10
    elif 'a'<=c<='z': n=n*62+ord(c)-ord('a')+36
    else: pass # ignore other chars
  return n

def parse_95( s: str ) -> int: # 95 = spc (32) incl till del (127) excl
  n = 0
  for c in s:
    assert 32<=ord(c)<127
    n=n*95+ord(c)-32 # ord(' ')
  return n

def format_62( n: int ) -> str:
  s = ''
  while n!=0:
    d = n%62
    if d>=36: s = (chr(ord('a')+d-36)) + s
    elif d>=10: s= (chr(ord('A')+d-10)) + s
    else: s = (chr(ord('0')+d)) + s
    n = n//62
  return s

def cvt_pwd_to_n( k: int, p: str ) -> int:
  if k==1: return int(p)
  if k==2: return int(p,16)
  if k==3: return parse_36(p)
  if k==4: return parse_62(p)
  if k==5: return parse_95(p)
  assert False

def clean( s: str ) -> str:
  return s.replace(" ", "").replace("\n", "")

import hashlib # not really needed, just for info/double-check

def md5( s: str ) -> str:
  h = hashlib.md5()
  h.update( s.encode('ascii') )
  return h.hexdigest()

def main():
  try:
    m = choose_mode()
    dhkx.set_modp( m )
    k = enter_kind()
    p = enter_pwd( k )
    a = cvt_pwd_to_n( k, p )
    u = dhkx.make_pub( a )
    g = format_62( u )
    print()
    print( 'Your public key:', g )
    print( 'Its MD5:', md5( g ) )
    print( 'Now send this key to your party.' )
    print()
    print( 'And receive a public key from your party.' )
    f = clean( input( 'Enter it here: ' ) )
    print( 'Its MD5:', md5( f ) )
    b = parse_62( f )
    c = dhkx.make_key( b, a )
    s = format_62( c )
    print()
    print( 'Your common secret password:', s )
    print( 'Its MD5:', md5( s ) )
  except EOFError:
    pass # hide all output when exiting on ^C

main()


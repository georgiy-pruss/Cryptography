# Password keeping program
VERS = "3.6"
# G.Pruss 2011.2.7,8,17 2012.5.9,9.16

PWFILE_DEFAULT_LOCATION = "C:\\Users\\.......\\Dropbox\\passwords.pws" # correct when moving!

import sys,zlib,hashlib,time,getpass
from rijncrypt3 import make_key, EncryptData, DecryptData, CryptError
try:
  from utils import p as pc, sc
except ImportError:
  def sc(x=None): pass
  def pc(x=None):
    if x==None: print()
    else: print(x,end="")

def help():
  sc("W")
  print("PW - PassWord keeper - Version "+VERS+" (Sep.2012) - with zlib,md5,aes/rijndael\n")
  print("pw.py xxx -- search (empty string \"\" to list all)")
  print("pw.py -s xxx -- search for starting with xxx")
  print("pw.py what name [pwd email-www-etc..] -- add record (use %20 for SPC)")
  print("pw.py -d index [index...] -- delete entries")
  print("pw.py -a file -- add records (TAB-separated) from file")
  print("pw.py -o file -- output to text file (TAB-separated records)")
  print("pw.py -i -- interactive (search,add(w/%20),delete)\n")
  print("the very first two arguments can be -f pwsfile\n")
  print("enter '?' as password to show password enternig")
  sc("w")

if len(sys.argv)>=4 and sys.argv[1]=="-f":
  PWFILE = sys.argv[2]
  ARGS = sys.argv[3:]
else:
  PWFILE = PWFILE_DEFAULT_LOCATION
  ARGS = sys.argv[1:]

'''
Pw           ('Pw' for zlib-compressed)
size/2       (0000..FEFF, 2 bytes, little-endian size of encrypted part, 0 to 65279)
             (FFxxxxxx, 4 bytes, 65280..16842495 -- will be implemented later)
encrypted:
  chksum/4   ~chksum/4   (chksum - bytes 2:6 of md5 of compressed data)
  compressed:
     utf-8-encoded data (prepended with "%08X" of current time, int seconds)
'''
def decrypt_data( data, password ):
  """data - binary, password - str"""
  return DecryptData( make_key( password.encode('utf-8') ), data )

def encrypt_data( data, password ):
  """data - binary, password - str"""
  return EncryptData( make_key( password.encode('utf-8') ), data )

def read_pw_file( path, password ):
  """read file; decrypt,uncompress'zlib',decode'utf-8',split
  return array of records (lines)"""
  try:
    f = open(path,"rb")
    sig = f.read(2)
    if sig!=b'Pw':  # signature for Pw -- zlib, short data (<64K)
      raise CryptError
    lng = f.read(2); lng = lng[0]*256+lng[1]
    data = f.read(lng)
    f.close()
    text = decrypt_data( data, password )
    h = text[0:4]
    g = text[4:8]
    if g != bytes( 0xFF^x for x in h ):
      raise CryptError
    compressed = text[8:]
    m = hashlib.md5()
    m.update(compressed)
    if m.digest()[2:6] != h:
      raise CryptError
    lines = zlib.decompress(compressed).decode('utf-8').split('\n')
  except IOError:
    print( "File '%s' not found/empty/read error" % path )
    return []
  except (CryptError,IndexError):
    print( "Wrong data or password")
    sys.exit(1)
  cr_time = int( lines[0][:8], 16 )
  lines[0] = lines[0][8:]
  print( len(lines),"records in '%s', last changed:"%path,
      time.strftime("%Y.%m.%d %H:%M:%S",time.localtime(cr_time)) )
  return sorted( lines, key=str.upper )

def write_pw_file( path, password, lines ):
  """write lines to file (join'\n',encode'utf-8',compress'zlib',checksum'md5',encrypt)
  (note: it always writes in Pw format now (using zlib, not bz2) - 20110217"""
  txt = "%08X"%int(time.time()) + '\n'.join(lines) # 1. randomizing 2. creat.time
  compressed = zlib.compress( txt.encode('utf-8'), 9 )
  m = hashlib.md5()
  m.update(compressed)
  h = m.digest()[2:6]
  g = bytes( 0xFF^x for x in h ) # ~h
  d = encrypt_data( h + g + compressed, password )
  l = len(d)
  assert l<0xFF00 # 255*256 = 65280
  f = open(path,"wb")
  f.write(bytes([0x50,0x77,l>>8,l&0xFF])) # new format -- only Pw, then size (<=64K)
  f.write(d)
  f.close()

def enter_pwd():
  p = getpass.getpass("password: ")
  if p.strip() == '?': # http://bugs.python.org/issue11272
    p = input("password: ")
  # since 3.2 it adds '\r'
  if p.endswith('\r'): p=p[:-1] # http://bugs.python.org/issue11272
  return p

def lengths(a):
  mi = m0 = m1 = m2 = 0
  for i,x in a:
    if i>mi: mi=i
    x = x.split("\t")
    if len(x[0])>m0: m0=len(x[0])
    if len(x[1])>m1: m1=len(x[1])
    if len(x)>2 and len(x[2])>m2: m2=len(x[2])
  return (len(str(mi)),m0,m1,m2)

def print_c(a,m):
  mi,m0,m1,m2 = m
  for i,x in a:
    sc("C"); pc("%%%dd. "%mi%(i+1))
    x = x.split("\t")
    sc("Y"); pc("%%-%ds"%(m0+1)%x[0])
    sc("W"); pc("%%-%ds"%(m1+1)%x[1])
    if len(x)>2: sc("M"); pc("%%-%ds"%(m2+1)%x[2])
    sc("w")
    if len(x)>3: pc(" ".join(x[3:]))
    pc()

def print_search(t,s,atstart=False):
  a = [] # answers
  if atstart:
    for i,x in enumerate(t):
      if x.upper().startswith(s):
        a.append( (i,x) )
  else:
    for i,x in enumerate(t):
      if s in x.upper():
        a.append( (i,x) )
  if a:
    print_c(a,lengths(a))
  else:
    print("no records found")

if len(ARGS)==1 and ARGS[0]!="-i" or len(ARGS)==2 and ARGS[0]=="-s": # search and print
  p = enter_pwd()
  t = read_pw_file( PWFILE, p )
  if len(t)==0:
    print( "No records to look through" )
    sys.exit(0)
  s = ARGS[-1].upper()
  print_search(t,s,len(ARGS)==2)
  #write_pw_file( PWFILE+"z", p, t ) -- for converting to newer format
  #print(len(t),"records written")

elif len(ARGS)>1 and ARGS[0][0:1]!="-": # add new record
  p = enter_pwd()
  t = read_pw_file( PWFILE, p )
  z = len(t)==0

  r = '\t'.join(sys.argv[1:]).replace("%20"," ")
  if r in t:
    print( "duplicated record" )
  else:
    t.append( r )
    print( "1 record added" )
    t = [l.strip() for l in t if len(l.strip())>0]
    if z: print( "File '%s' will be created" % PWFILE )
    write_pw_file( PWFILE, p, t )
    print(len(t),"records written")

elif len(ARGS)==2 and ARGS[0]=="-a": # add from file
  p = enter_pwd()
  t = read_pw_file( PWFILE, p )
  z = len(t)==0

  n = 0
  for l in open(ARGS[1],"rt"):
    l = l.strip()
    if len(l)==0: continue
    r = '\t'.join( [x.replace("%20"," ") for x in l.split("\t")] )
    if r not in t:
      t.append( r )
      n += 1
    else:
      print( "duplicated:", " ".join( r.split("\t")[:2] ) )
  print( n, "records added" )

  if n>0:
    t = [l.strip() for l in t if len(l.strip())>0]
    if z: print( "File '%s' will be created" % PWFILE )
    write_pw_file( PWFILE, p, t )
    print(len(t),"records written")

elif len(ARGS)==2 and ARGS[0]=="-o": # output to file
  p = enter_pwd()
  t = read_pw_file( PWFILE, p )
  o = open(ARGS[1],"wt")
  for x in t:
    print(x.replace(" ","%20"),file=o)
  o.close()
  print(len(t),"records written to file '%s'"%ARGS[1])

elif len(ARGS)>1 and ARGS[0]=="-d": # delete records
  p = enter_pwd()
  t = read_pw_file( PWFILE, p )
  delrecs = sorted( [int(n) for n in ARGS[1:]] )
  fmt = "%%%dd."%len(str(delrecs[0]))
  for n in delrecs:
    print(fmt%n,"\t".join(t[n-1].split("\t")[:2]))
  for n in delrecs[::-1]: # in desc. order! it's important for 'del'
    del t[n-1]
  print(len(delrecs),"records deleted,",len(t),"records left")
  write_pw_file( PWFILE, p, t )

elif len(ARGS)==1 and ARGS[0]=="-i": # interactive
  p = enter_pwd()
  t = read_pw_file( PWFILE, p )
  z = len(t)==0
  sc("C")
  print("xxx... -- search\na xxx... -- add (separate with SPC, use %20 for SPC)")
  print("d # #... -- delete\nq -- exit")
  sc("w")
  try:
    o = input("> ")
    while o!='q':
      if o.find(" ") < 0: # one word, search for it
        print_search(t,o.upper().replace("%20"," "))
      elif o.startswith("a "):
        r = '\t'.join(o[2:].split()).replace("%20"," ")
        if r in t:
          print( "duplicated record" )
        else:
          t.append( r )
          print( "1 record added" )
          t = [l.strip() for l in t if len(l.strip())>0]
          if z: print( "File '%s' will be created" % PWFILE )
          z = False
          write_pw_file( PWFILE, p, t )
          print(len(t),"records written")
      elif o.startswith("d "):
        delrecs = sorted( list( set( int(n) for n in o[2:].split() if 0<int(n)<=len(t) ) ) )
        a = [(n,t[n-1]) for n in delrecs]
        mi,m0 = lengths(a)[:2]
        for n in delrecs:
          x,y = t[n-1].split("\t")[:2]
          sc("C"); pc("%%%dd. "%mi%n); sc("Y"); pc("%%-%ds "%m0%x); sc("W"); pc(y+"\n")
        sc("w")
        for n in delrecs[::-1]: # in desc. order! it's important for 'del'
          del t[n-1]
        print(len(delrecs),"records deleted,",len(t),"records left")
        write_pw_file( PWFILE, p, t )
        z = len(t)==0
      o = input("> ")
  except KeyboardInterrupt:
    pass

else: # help and exit
  help()


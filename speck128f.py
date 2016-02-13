#!/usr/bin/env python
import speck128, sys

if len(sys.argv)<3:
  print("speck128f.py [password] input output")
else:
  def I(b:bytes)->int: return int.from_bytes(b,'big')
  def B(n:int)->bytes: return n.to_bytes(16,'big')
  if len(sys.argv)==4: pw = sys.argv[1]
  else: pw = input("password: ")
  xk = speck128.expand_key(32,I(pw.encode('utf-8')))
  with open(sys.argv[-2],"rb") as f: t = f.read()
  l = len(t); k = l%16
  with open(sys.argv[-1],"wb") as f:
    for i in range(0,l-k,16):
      f.write(B(speck128.encrypt(xk,i) ^ I(t[i:i+16])))
    if k>0:
      f.write(B(speck128.encrypt(xk,l) ^ I(t[-k:]+b'='*(16-k)))[:k])

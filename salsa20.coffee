# From NaCL-20110221 package; crypto_core; by D. J. Bernstein
# Modified by G. Pruss (C) 2015

R = (u,c) -> ((u)<<c) | ((u)>>>(32-c))

U4B = (x,i) -> x[i] | (x[i+1]<<8) | (x[i+2]<<16) | (x[i+3]<<24)

X4U = (x,i,u) -> x[i]^=u&0xFF; u>>>=8; x[i+1]^=u&0xFF; u>>>=8; x[i+2]^=u&0xFF; u>>>=8; x[i+3]^=u&0xFF

salsa20 = ( d, k, v, ctr, n ) ->
  t0=0x61707865; t1=U4B(k,0);  t2=U4B(k,4);  t3=U4B(k,8);  t4=U4B(k,12)
  t5=0x3320646e; t6=U4B(v,0);  t7=U4B(v,4);  t8=ctr;       t9=0
  ta=0x79622d32; tb=U4B(k,16); tc=U4B(k,20); td=U4B(k,24); te=U4B(k,28)
  tf=0x6b206574; o=0
  while n-- > 0 # for j in [0...n] -- slow
    x0=t0; x1=t1; x2=t2; x3=t3; x4=t4; x5=t5; x6=t6; x7=t7; x8=t8; x9=t9
    xa=ta; xb=tb; xc=tc; xd=td; xe=te; xf=tf
    i=20
    while i>0
      x4 ^= R(x0+xc,7); x8 ^= R(x4+x0,9); xc ^= R(x8+x4,13); x0 ^= R(xc+x8,18)
      x9 ^= R(x5+x1,7); xd ^= R(x9+x5,9); x1 ^= R(xd+x9,13); x5 ^= R(x1+xd,18)
      xe ^= R(xa+x6,7); x2 ^= R(xe+xa,9); x6 ^= R(x2+xe,13); xa ^= R(x6+x2,18)
      x3 ^= R(xf+xb,7); x7 ^= R(x3+xf,9); xb ^= R(x7+x3,13); xf ^= R(xb+x7,18)
      x1 ^= R(x0+x3,7); x2 ^= R(x1+x0,9); x3 ^= R(x2+x1,13); x0 ^= R(x3+x2,18)
      x6 ^= R(x5+x4,7); x7 ^= R(x6+x5,9); x4 ^= R(x7+x6,13); x5 ^= R(x4+x7,18)
      xb ^= R(xa+x9,7); x8 ^= R(xb+xa,9); x9 ^= R(x8+xb,13); xa ^= R(x9+x8,18)
      xc ^= R(xf+xe,7); xd ^= R(xc+xf,9); xe ^= R(xd+xc,13); xf ^= R(xe+xd,18)
      i -= 2
    x0 += t0; x1 += t1; x2 += t2; x3 += t3; x4 += t4; x5 += t5; x6 += t6; x7 += t7
    x8 += t8; x9 += t9; xa += ta; xb += tb; xc += tc; xd += td; xe += te; xf += tf
    X4U( d,o   ,x0 ); X4U( d,o+ 4,x1 ); X4U( d,o+ 8,x2 ); X4U( d,o+12,x3 )
    X4U( d,o+16,x4 ); X4U( d,o+20,x5 ); X4U( d,o+24,x6 ); X4U( d,o+28,x7 )
    X4U( d,o+32,x8 ); X4U( d,o+36,x9 ); X4U( d,o+40,xa ); X4U( d,o+44,xb )
    X4U( d,o+48,xc ); X4U( d,o+52,xd ); X4U( d,o+56,xe ); X4U( d,o+60,xf )
    o+=64; ++t8
  return t8

test0 = ->
  k = (0 for i in [0...32])
  v = (0 for i in [0...8])
  d = (0 for i in [0...64])
  salsa20( d, k, v, 0, 1 )
  r = ((if x<16 then "0"+x.toString(16) else x.toString(16)) for x in d).join('')
  r == "9a97f65b9b4c721b"+"960a672145fca8d4"+"e32e67f9111ea979"+"ce9c4826806aeee6"+
       "3de9c0da2bd7f91e"+"bcb2639bf989c625"+"1b29bf38d39a9bdc"+"e7c55f4b2ac12a39"
  
say = if window? then alert else console.log # good both for node.js and browser

if test0()
  M = 500000
  t1 = (new Date).getTime()
  for i in [1..M] # this translates to really weird code!
    test0()
  t2 = (new Date).getTime()
  td = if t1==t2 then 1 else t2-t1
  say "#{td/1000}s for #{M} encodings, or #{(M*64/td)//1/1000}MB/s"
else
  say "ERROR!"

# 1.63 node.js / 2.68 firefox

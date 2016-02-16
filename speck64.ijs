NB. speck 64 bit block - 128 bit key - 27 rounds --- for 64-bit architecture

'`AND OR XOR SHL' =: (17 b.)`(23 b.)`(22 b.)`(33 b.) NB. last is shift-left
ROL =: 16bffffffff AND SHL OR (_32+[) SHL ] NB. rotate-left

expandkey =: 3 : 0 NB. y - 16 bytes (numbers, like 16?256)
  assert. 16=#y
  k =. 256#. _4{.y
  l =. 0$0 for_i. i.3 do. l =. l, 256#. _4{. y =. _4}.y end.
  for_i. i. 26 do. NB. for 27 rounds - https://en.wikipedia.org/wiki/Speck_(cipher)
    l =. l, u =. i XOR 16bffffffff AND (i{k) + 24 ROL i{l
    k =. k, v =. u XOR 3 ROL i{k
  end.
  k NB. (#k) = 27 - number of rounds
)

encrypt =: 4 : 0 NB. x - exp.key (27 numbers), y - 8 bytes (numbers, like 8?256)
  R =. 256#. 4}.y [ L =. 256#. 4{.y
  for_k. x do. R =. (3 ROL R) XOR L =. k XOR 16bffffffff AND R + 24 ROL L end.
  (256 256 256 256#:L),256 256 256 256#:R
  NB. a.i. (_4{.0 (3!:1) L),_4{.0 (3!:1) R NB. probably better if 'bytes' interface
  NB. |.a.i.(2(3!:4)R),2(3!:4)L NB. also a bit slower, between the above
)

decrypt =: 4 : 0 NB. x - exp.key (27 numbers), y - 8 bytes (ciphertext)
  R =. 256#. 4}.y [ L =. 256#. 4{.y
  for_k. |.x do. L =. 8 ROL 16bffffffff AND (L XOR k) - R =. 29 ROL L XOR R end.
  (256 256 256 256#:L),256 256 256 256#:R
)

X =: _2 dfh\] NB. dfh is predefined as 16#.16|'0123456789ABCDEF0123456789abcdef'i.]

xk =: expandkey X'1b1a1918131211100b0a090803020100'
pt =: X'3b7265747475432d' NB. b'-Cutter;'
ct =: X'8c6fa548454e028b'
assert ct = xk encrypt pt
assert pt = xk decrypt ct

test =: 3 : 0 NB. y - number of repeats
  start =. 6!:1''
  pt=.8?256
  for_i. i.y do.
    ct =. xk encrypt pt
    rt =. xk decrypt ct
    assert. pt = rt
    pt =. ct
  end.
  echo -start-6!:1''
)

test 100000 NB. 30s

exit 0

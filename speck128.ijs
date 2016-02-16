NB. speck 128 bit block - 128/192/256 bit key - 32/33/34 rounds

'`AND OR XOR SHL ROL'=: (17 b.)`(23 b.)`(22 b.)`(33 b.)`(32 b.) NB. l-shift, rot-l-shift
ADD =: (+&(_32&SHL) (32&SHL@(+ _32&SHL) OR AND&16bffffffff@]) +&(AND&16bffffffff))"0
INT =: OR/ @: (56 48 40 32 24 16 8 0&SHL)


expandkey =: 3 : 0 NB. y - 16/26/32 bytes (numbers)
  keysz=.#key=.y NB. keysz is 16/24/32 for 128/192/256-bit int key
  assert. keysz e. 16 24 32
  m =. keysz%8 NB. number of 64-bit words in key: 2/3/4
  k =. INT _8{.key
  l =. 0#0
  for_i. i.<:m do.
    key =. _8}.key
    l =. l,INT _8{.key
  end.
  for_i. i. 30+<:m do.
    u =. i XOR (i{k)ADD _8 ROL i{l
    l =. l,u
    v =. u XOR 3 ROL i{k
    k =. k,v
  end.
  k NB. #k = 32/33/34 - number of rounds
)

encrypt =: 4 : 0 NB. x - exp.key (32/33/34), y - 16 bytes (numbers)
  assert. (#x) e. 32 33 34
  L =. INT 8{.y
  R =. INT 8}.y
  for_i. x do.
    L =. i XOR R ADD _8 ROL L
    R =. L XOR 3 ROL R
  end.
  ((8#256)#:L),(8#256)#:R
)

decrypt =: 4 : 0 NB. x - exp.key (32/33/34), y - 16 numbers
  assert. (#x) e. 32 33 34
  L =. INT 8{.y
  R =. INT 8}.y
  for_i. |.x do.
    R =. _3 ROL L XOR R
    L =. 8 ROL (L XOR i) ADD -R
  end.
  ((8#256)#:L),(8#256)#:R
)

X =: _2 dfh\] NB. dfh is predefined as 16#.16|'0123456789ABCDEF0123456789abcdef'i.]

xk =: expandkey i._16
pt =: X'6c617669757165207469206564616d20'
ct =: xk encrypt pt
assert ct=X'a65d9851797832657860fedf5c570d18'
rt =: xk decrypt ct
assert rt=pt

xk =: expandkey i._24
pt =: X'726148206665696843206f7420746e65'
ct =: xk encrypt pt
assert ct=X'1be4cf3a13135566f9bc185de03c1886'
rt =: xk decrypt ct
assert rt=pt

xk =: expandkey i._32
pt =: X'65736f6874206e49202e72656e6f6f70'
ct =: xk encrypt pt
assert ct=X'4109010405c0f53e4eeeb48d9c188f43'
rt =: xk decrypt ct
assert rt=pt

test =: 3 : 0
  start =. 6!:1''
  pt=.16?256
  for_i. i.y do.
    ct =. xk encrypt pt
    rt =. xk decrypt ct
    assert. pt=rt
    pt =. ct
  end.
  echo -start-6!:1'' NB. 100000 -- 40s
)

test 100000

exit 0

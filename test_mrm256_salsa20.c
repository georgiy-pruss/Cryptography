/* Test suite for mrm256 and salsa20 -- can be included in salsa20.c */

B s0[] = "7cd81e80579a116641562931dc345f9e3e3661a6a2de88e0abbc07f23a0bd941";
B s1[] = "aadab6da5ad3c4dad83f2f3a5fddad0791074eda25a9b377ecccddf0b2e04601";
B s2[] = "4b96f874df352e68487a6a5ad8d766893ab1194038293491949034cb840e06b2";

B e0[] = "9a97f65b9b4c721b" "960a672145fca8d4" "e32e67f9111ea979" "ce9c4826806aeee6"
         "3de9c0da2bd7f91e" "bcb2639bf989c625" "1b29bf38d39a9bdc" "e7c55f4b2ac12a39";

B k0[] = "0102030405060708" "090A0B0C0D0E0F10" "1112131415161718" "191A1B1C1D1E1F20";
B v0[] = "0301040105090206";
B r0[] = "a305a2b950e19506" "1a8894aa2cb1b7ad" "d442897916701026" "a4b1ed643f17272d"
         "faf1c7b1dc6e0662" "23fa35e0046f49c4" "b3e6312128de0b81" "07b42cf63ddede6b";

B k1[] = "8000000000000000" "0000000000000000" "0000000000000000" "0000000000000000";

B b1[] = "E3BE8FDD8BECA2E3EA8EF9475B29A6E7003951E1097A5C38D23B7A5FAD9F6844"
         "B22C97559E2723C7CBBD3FE4FC8D9A0744652A83E72A9C461876AF4D7EF1A117";
B m1[] = "57BE81F47B17D9AE7C4FF15429A73E10ACF250ED3A90A93C711308A74C6216A9"
         "ED84CD126DA7F28E8ABF8BB63517E1CA98E712F4FB2E1A6AED9FDC73291FAA17"
         "958211C4BA2EBD5838C635EDB81F513A91A294E194F1C039AEEC657DCE40AA7E"
         "7C0AF57CACEFA40C9F14B71A4B3456A63E162EC7D8D10B8FFB1810D71001B618";
B e1[] = "696AFCFD0CDDCC83C7E77F11A649D79ACDC3354E9635FF137E929933A0BD6F53"
         "77EFA105A3A4266B7C0D089D08F1E855CC32B15B93784A36E56A76CC64BC8477";

V s2v( const char* s, B* v, int n ) __
  int i,k; for(i=0;i<n;++i) { sscanf(s+2*i,"%2x",&k); v[i]=(B)k; } _

int test() __ B d[512], r[512], k[32], v[8]; int e=0,ee=0;
  mrm256( r, "", 0 ); s2v(s0,d,32); if( memcmp(r,d,32)!=0 ) ++e;
  mrm256( r, "hello", 5 ); s2v(s1,d,32); if( memcmp(r,d,32)!=0 ) ++e;
  memset(d,0x5A,96); mrm256( r, d, 96 ); s2v(s2,d,32); if( memcmp(r,d,32)!=0 ) ++e;
  if(e) printf("Error mrm256 (%d)\n",e);

  memset(k,0,32); memset(v,0,8); memset(d,0,64);
  salsa20( d, k, v, 0, 1 );
  s2v(e0,r,64); if( memcmp(d,r,64)!=0 ) ++e,printf("Error encoding zeros\n");

  s2v(k0,k,32); s2v(v0,v,8); memset(d,0,64);
  salsa20( d, k, v, 7, 1 );
  s2v(r0,r,64); if( memcmp(d,r,64)!=0 ) ++e,printf("Error encoding k0,v0\n");
  salsa20( d, k, v, 7, 1 ); /* "decode" */
  memset(r,0,64); if( memcmp(d,r,64)!=0 ) ++e,printf("Error decoding k0,v0\n");

  s2v(k1,k, 32); memset(v,0,8); memset(d,0,512);
  salsa20( d, k, v, 0, 512/64 );
  s2v(b1,r, 64); if( memcmp(d,r,64)!=0 ) ++ee;
  s2v(m1,r,128); if( memcmp(d+256-64,r,128)!=0 ) ++ee;
  s2v(e1,r, 64); if( memcmp(d+512-64,r,64)!=0 ) ++ee;
  if(ee) printf("Error encoding 512 (%d)\n",ee);
  return e+ee; _

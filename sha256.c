/* From NaCL-20110221 package; crypto_hash*; by D. J. Bernstein */
/* Modified a bit by G. Pruss (C) 2015 */

typedef unsigned char B;
typedef unsigned int  U;
typedef unsigned long long L;
#define V void

#define __ {
#define _  }

static U LBE(const B* x) { return (U)x[3] | ((U)x[2] << 8) | ((U)x[1] << 16) | ((U)x[0] << 24); }

static V SBE(B* x, U u) { x[3] = u; u >>= 8; x[2] = u; u >>= 8; x[1] = u; u >>= 8; x[0] = u; }

#define SHR(x,c) ((x) >> (c))
#define ROTR(x,c) (((x) >> (c)) | ((x) << (32 - (c))))

#define Ch(x,y,z) ((x & y) ^ (~x & z))
#define Maj(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define Sigma0(x) (ROTR(x, 2) ^ ROTR(x,13) ^ ROTR(x,22))
#define Sigma1(x) (ROTR(x, 6) ^ ROTR(x,11) ^ ROTR(x,25))
#define sigma0(x) (ROTR(x, 7) ^ ROTR(x,18) ^ SHR(x, 3))
#define sigma1(x) (ROTR(x,17) ^ ROTR(x,19) ^ SHR(x,10))

#define M(w0,w14,w9,w1) w0 = sigma1(w14) + w9 + sigma0(w1) + w0;

#define EXPAND \
  M(w0 ,w14,w9 ,w1 ) M(w1 ,w15,w10,w2 ) M(w2 ,w0 ,w11,w3 ) M(w3 ,w1 ,w12,w4 ) \
  M(w4 ,w2 ,w13,w5 ) M(w5 ,w3 ,w14,w6 ) M(w6 ,w4 ,w15,w7 ) M(w7 ,w5 ,w0 ,w8 ) \
  M(w8 ,w6 ,w1 ,w9 ) M(w9 ,w7 ,w2 ,w10) M(w10,w8 ,w3 ,w11) M(w11,w9 ,w4 ,w12) \
  M(w12,w10,w5 ,w13) M(w13,w11,w6 ,w14) M(w14,w12,w7 ,w15) M(w15,w13,w8 ,w0 )

#define F(w,k) \
  T1 = h + Sigma1(e) + Ch(e,f,g) + k + w; T2 = Sigma0(a) + Maj(a,b,c); \
  h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

V blocks( B* sb, const B* in, L inlen ) __
  U s[8]; U a, b, c, d, e, f, g, h, T1, T2;
  s[0] = a = LBE(sb +  0); s[1] = b = LBE(sb +  4); s[2] = c = LBE(sb +  8); s[3] = d = LBE(sb + 12);
  s[4] = e = LBE(sb + 16); s[5] = f = LBE(sb + 20); s[6] = g = LBE(sb + 24); s[7] = h = LBE(sb + 28);
  for( ; inlen >= 64; in += 64, inlen -= 64 ) __
    U w0  = LBE(in +  0); U w1  = LBE(in +  4); U w2  = LBE(in +  8); U w3  = LBE(in + 12);
    U w4  = LBE(in + 16); U w5  = LBE(in + 20); U w6  = LBE(in + 24); U w7  = LBE(in + 28);
    U w8  = LBE(in + 32); U w9  = LBE(in + 36); U w10 = LBE(in + 40); U w11 = LBE(in + 44);
    U w12 = LBE(in + 48); U w13 = LBE(in + 52); U w14 = LBE(in + 56); U w15 = LBE(in + 60);
    F(w0 ,0x428a2f98) F(w1 ,0x71374491) F(w2 ,0xb5c0fbcf) F(w3 ,0xe9b5dba5)
    F(w4 ,0x3956c25b) F(w5 ,0x59f111f1) F(w6 ,0x923f82a4) F(w7 ,0xab1c5ed5)
    F(w8 ,0xd807aa98) F(w9 ,0x12835b01) F(w10,0x243185be) F(w11,0x550c7dc3)
    F(w12,0x72be5d74) F(w13,0x80deb1fe) F(w14,0x9bdc06a7) F(w15,0xc19bf174)
    EXPAND
    F(w0 ,0xe49b69c1) F(w1 ,0xefbe4786) F(w2 ,0x0fc19dc6) F(w3 ,0x240ca1cc)
    F(w4 ,0x2de92c6f) F(w5 ,0x4a7484aa) F(w6 ,0x5cb0a9dc) F(w7 ,0x76f988da)
    F(w8 ,0x983e5152) F(w9 ,0xa831c66d) F(w10,0xb00327c8) F(w11,0xbf597fc7)
    F(w12,0xc6e00bf3) F(w13,0xd5a79147) F(w14,0x06ca6351) F(w15,0x14292967)
    EXPAND
    F(w0 ,0x27b70a85) F(w1 ,0x2e1b2138) F(w2 ,0x4d2c6dfc) F(w3 ,0x53380d13)
    F(w4 ,0x650a7354) F(w5 ,0x766a0abb) F(w6 ,0x81c2c92e) F(w7 ,0x92722c85)
    F(w8 ,0xa2bfe8a1) F(w9 ,0xa81a664b) F(w10,0xc24b8b70) F(w11,0xc76c51a3)
    F(w12,0xd192e819) F(w13,0xd6990624) F(w14,0xf40e3585) F(w15,0x106aa070)
    EXPAND
    F(w0 ,0x19a4c116) F(w1 ,0x1e376c08) F(w2 ,0x2748774c) F(w3 ,0x34b0bcb5)
    F(w4 ,0x391c0cb3) F(w5 ,0x4ed8aa4a) F(w6 ,0x5b9cca4f) F(w7 ,0x682e6ff3)
    F(w8 ,0x748f82ee) F(w9 ,0x78a5636f) F(w10,0x84c87814) F(w11,0x8cc70208)
    F(w12,0x90befffa) F(w13,0xa4506ceb) F(w14,0xbef9a3f7) F(w15,0xc67178f2)
    a += s[0]; b += s[1]; c += s[2]; d += s[3]; e += s[4]; f += s[5]; g += s[6]; h += s[7];
    s[0] = a; s[1] = b; s[2] = c; s[3] = d; s[4] = e; s[5] = f; s[6] = g; s[7] = h; _
  SBE(sb +  0,s[0]); SBE(sb +  4,s[1]); SBE(sb +  8,s[2]); SBE(sb + 12,s[3]);
  SBE(sb + 16,s[4]); SBE(sb + 20,s[5]); SBE(sb + 24,s[6]); SBE(sb + 28,s[7]); _

static const B iv[32] = __
  0x6a,0x09,0xe6,0x67, 0xbb,0x67,0xae,0x85, 0x3c,0x6e,0xf3,0x72, 0xa5,0x4f,0xf5,0x3a,
  0x51,0x0e,0x52,0x7f, 0x9b,0x05,0x68,0x8c, 0x1f,0x83,0xd9,0xab, 0x5b,0xe0,0xcd,0x19 _;

V sha256( B* out, const B* in, L inlen ) __ int i;
  B h[32], padded[128]; L bits = inlen << 3;
  for(i = 0;i < 32;++i) h[i] = iv[i];
  blocks(h,in,inlen); in += inlen; inlen &= 63; in -= inlen;
  for(i = 0;i < inlen;++i) padded[i] = in[i]; padded[inlen] = 0x80;
  if(inlen < 56) __
    for(i = inlen + 1;i < 56;++i) padded[i] = 0;
    padded[56] = bits >> 56; padded[57] = bits >> 48;
    padded[58] = bits >> 40; padded[59] = bits >> 32;
    padded[60] = bits >> 24; padded[61] = bits >> 16;
    padded[62] = bits >>  8; padded[63] = bits;
    blocks(h,padded,64); _
  else __
    for(i = inlen + 1;i < 120;++i) padded[i] = 0;
    padded[120] = bits >> 56; padded[121] = bits >> 48;
    padded[122] = bits >> 40; padded[123] = bits >> 32;
    padded[124] = bits >> 24; padded[125] = bits >> 16;
    padded[126] = bits >>  8; padded[127] = bits;
    blocks(h,padded,128); _
  for(i = 0;i < 32;++i) out[i] = h[i]; _

/* Usage: B sha[32]; sha256( sha, data, data_size ); */

/* ""       -> x"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
   "hello"  -> x"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
   x'7C'*60 -> x"d20f53d743694859e718f8516ed7e4420190ad9d635a3251ae724b8a488c9326" */ 

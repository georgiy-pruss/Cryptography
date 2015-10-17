/* 256-bit hash function, by G. Pruss 2015; based on MurmurHash3_x64_128: */
/* https://en.wikipedia.org/wiki/MurmurHash & https://code.google.com/p/smhasher/ */

#include <string.h>

typedef unsigned char B;
typedef unsigned int  U;
typedef unsigned long long L;
#define V void

#define __ {
#define _  }

V mrm128( L* out, const L* data, int len, int k ) __ L x; /* ~ MurmurHash3_x64_128 */
  #define R64(x,y) (((x)<<(y))|((x)>>(64-(y))))
  #define MRM(d,c1,n,c2,h) x=d*c1; x=R64(x,n); x*=c2; h^=x
  #define MIX(k) ((k^=(k>>33)), (k*=0xff51afd7ed558ccdULL), \
                  (k^=(k>>33)), (k*=0xc4ceb9fe1a85ec53ULL), (k^=(k>>33)))
  const int nblocks = len / (2*sizeof(L)); /* one block is 2 L-words */
  const L c1 = 0x87c37b91114253d5ULL, c2 = 0x4cf5ad432745937fULL;
  L h1 = k ? 0x32ac3b17a1e38b93ULL : 0x561ccd1b38b34ae5ULL;
  L h2 = k ? 0x96cd1c35239b9610ULL : 0x0bcaa747ab0e9789ULL;
  for( int i = 0; i < nblocks; ++i ) __
    MRM(data[i*2],  c1,31,c2,h1); h1 = R64(h1,27); h1 += h2; h1 = h1*5+0x52dce729;
    MRM(data[i*2+1],c2,33,c1,h2); h2 = R64(h2,31); h2 += h1; h2 = h2*5+0x38495ab5; _
  const int rest = len & 15; L z[2]={0,0}; memcpy(z,data+nblocks*2,rest);
  if( rest>8 ) { MRM(z[1],c2,33,c1,h2); } if( rest>0 ) { MRM(z[0],c1,31,c2,h1); }
  h1 ^= len; h2 ^= len; h1 += h2; h2 += h1;
  MIX(h1); MIX(h2);     h1 += h2; h2 += h1; out[0] = h1; out[1] = h2; _

#define mrm256(o,d,l) (mrm128((L*)(o),(L*)(d),l,0),mrm128((L*)(o)+2,(L*)(d),l,1))

/* 256-bit hash function, by G. Pruss 205; based on MurmurHash3_x64_128; See: */
/* https://en.wikipedia.org/wiki/MurmurHash & https://code.google.com/p/smhasher/ */
/* compile with: gcc -O3 -std=c99 mrm256test.c -o mrm256test */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/timeb.h>

typedef unsigned char B;
typedef unsigned int  U;
typedef unsigned long long L;
#define V void

#define __ {
#define _  }

#include "mrm256.c"

#define P(s,b,n) {printf("%s ",(s));int i;for(i=0;i<(n);++i)printf("%02x",(b)[i]);printf("\n");}

int main( int ac, char* av[] ) __
  if( ac==1 ) __
    B data[80]; B out[32]; /* 256 bit */ int i,j,k;
    memset( data, 57, 80 );
    memset( data,  0, 40 );
    memcpy( data, "ABCDEFGH", 9 );
    for( i=0; i<=80; ++i ) __
      printf( "%2d",i );
      mrm256( out, data, i ); P("",out,32); _
    if(1) __ /* test */ int cntr[256] = {0};
      /* FILE* fo; fo = fopen("m.n","wb");
      mrm256( out, data, 0 ); fwrite( out, 1, 32, fo );
      for( i=0; i<256; ++i ) { data[0]=i; mrm256( out, data, 1 ); fwrite( out, 1, 32, fo ); }
      for( i=0; i<256; ++i )
        for( j=0; j<256; ++j )
          { data[0]=i; data[1]=j; mrm256( out, data, 2 ); fwrite( out, 1, 32, fo ); }
      for( i=0; i<256; ++i )
        for( j=0; j<256; ++j )
          for( k=0; k<256; ++k )
            { data[0]=i; data[1]=j; data[2]=k; mrm256( out, data, 3 ); fwrite( out, 1, 32, fo ); }
      fwrite( out, 1, 32, fo ); fclose(fo); */
      for( i=0; i<8000000; ++i ) __
        sprintf(data,"%4d",i); mrm256( out, data, 5 );
        for( j=0; j<32; ++j )
          ++cntr[out[j]]; _
      for( i=0; i<256; ++i )
        printf("%3d %6d %c",i,cntr[i]-1000000,(i%8)==7?'\n':' ');
      _ _
  else __ /* time it! 1745 MB/s at work for 2GB file */
    struct timeb t0,t1;
    B buf[64*10000]; B h[32]; int n; L m;
    FILE* fi = fopen(av[1],"rb"); if(!fi) return 1;
    ftime(&t0);
    for(m=0;;m+=n) __
      n = fread( buf, 1, sizeof(buf), fi ); if(n==0) break;
      mrm256(h,buf,n); _
    P("h",h,32);
    fclose(fi);
    ftime(&t1);
    double tt = t1.time-t0.time + (t1.millitm-t0.millitm)/1e3; if(tt==0.0) tt=0.001;
    printf("%.1f s, %.1f MB/s", tt, m/1e6/tt); _
  return 0; _

/* gcc -O3 -S -fverbose-asm -g mrm256.c && as -alhnd mrm256.s >mrm256.t */

/* JFYI
0x87c37b91114253d5 =  9782798678568883157 :: 157 2033401 30643645601
0x4cf5ad432745937f =  5545529020109919103 :: 191 29034183351360833
0xff51afd7ed558ccd = 18397679294719823053 :: 18397679294719823053
0xc4ceb9fe1a85ec53 = 14181476777654086739 :: 18341 930763 830728933
0x52dce729 = 1390208809 :: 11 11 11489329
0x38495ab5 =  944331445 :: 5 19 9940331
0x32ac3b17a1e38b93 =  3651358370576960403 :: 3 3 3 135235495206554089
0x561ccd1b38b34ae5 =  6205059903408786149 :: 17 37 149 21391 3095123459
0x96cd1c35239b9610 = 10866372490471118352 :: 2 2 2 2 3 28637933 7904996503
0x0bcaa747ab0e9789 =   849675405967136649 :: 3 3 571 165338666271091
*/

/* From NaCL-20110221 package; crypto_core; by D. J. Bernstein */
/* Modified by G. Pruss (C) 2015 | compile with -std=c99 */

typedef unsigned char B;
typedef unsigned int  U;
#define V void

#define __ {
#define _  }

#define R(u,c) (((u)<<c)|((u)>>(32-c)))

static U U4B(const B* x) { return (U)x[0] | ((U)x[1]<<8) | ((U)x[2]<<16) | ((U)x[3]<<24); }

static V X4U(B* x,U u) { x[0]^=u; u>>=8; x[1]^=u; u>>=8; x[2]^=u; u>>=8; x[3]^=u; }

U salsa20( B* d, const B k[32], const B v[8], U ctr, U n ) __
  U x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,xa,xb,xc,xd,xe,xf;
  U t0,t1,t2,t3,t4,t5,t6,t7,t8,t9,ta,tb,tc,td,te,tf;
  t0=0x61707865; /* expa */ t1=U4B(k);    t2=U4B(k+4);  t3=U4B(k+8);  t4=U4B(k+12);
  t5=0x3320646e; /* nd 3 */ t6=U4B(v);    t7=U4B(v+4);  t8=ctr;       t9=0;
  ta=0x79622d32; /* 2-by */ tb=U4B(k+16); tc=U4B(k+20); td=U4B(k+24); te=U4B(k+28);
  tf=0x6b206574; /* te k */                  /* only one word t8 is used as counter */
  for( U j=0; j<n; ++j, d+=64, ++t8 ) __     /* thus allowing only 256 GiB of data */
    x0=t0; x1=t1; x2=t2; x3=t3; x4=t4; x5=t5; x6=t6; x7=t7; x8=t8; x9=t9;
    xa=ta; xb=tb; xc=tc; xd=td; xe=te; xf=tf; /* setting t* outside gave +5% perf. */
    for( int i=20; i>0; i-=2 ) __
      x4 ^= R(x0+xc,7); x8 ^= R(x4+x0,9); xc ^= R(x8+x4,13); x0 ^= R(xc+x8,18);
      x9 ^= R(x5+x1,7); xd ^= R(x9+x5,9); x1 ^= R(xd+x9,13); x5 ^= R(x1+xd,18);
      xe ^= R(xa+x6,7); x2 ^= R(xe+xa,9); x6 ^= R(x2+xe,13); xa ^= R(x6+x2,18);
      x3 ^= R(xf+xb,7); x7 ^= R(x3+xf,9); xb ^= R(x7+x3,13); xf ^= R(xb+x7,18);
      x1 ^= R(x0+x3,7); x2 ^= R(x1+x0,9); x3 ^= R(x2+x1,13); x0 ^= R(x3+x2,18);
      x6 ^= R(x5+x4,7); x7 ^= R(x6+x5,9); x4 ^= R(x7+x6,13); x5 ^= R(x4+x7,18);
      xb ^= R(xa+x9,7); x8 ^= R(xb+xa,9); x9 ^= R(x8+xb,13); xa ^= R(x9+x8,18);
      xc ^= R(xf+xe,7); xd ^= R(xc+xf,9); xe ^= R(xd+xc,13); xf ^= R(xe+xd,18); _
    x0 += t0; x1 += t1; x2 += t2; x3 += t3; x4 += t4; x5 += t5; x6 += t6; x7 += t7;
    x8 += t8; x9 += t9; xa += ta; xb += tb; xc += tc; xd += td; xe += te; xf += tf;
    X4U( d+ 0,x0 ); X4U( d+ 4,x1 ); X4U( d+ 8,x2 ); X4U( d+12,x3 );
    X4U( d+16,x4 ); X4U( d+20,x5 ); X4U( d+24,x6 ); X4U( d+28,x7 );
    X4U( d+32,x8 ); X4U( d+36,x9 ); X4U( d+40,xa ); X4U( d+44,xb );
    X4U( d+48,xc ); X4U( d+52,xd ); X4U( d+56,xe ); X4U( d+60,xf ); _
  return t8; _

/* Now let's use salsa20 for encrypting/decrypting files; use mrm256 for first 10 MB */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/timeb.h>

#include "mrm256.c" /* let's use mrm256 instead of sha256 -- it's much faster */
#include "test_mrm256_salsa20.c" /* int test(), ok if 0 */

V generate_iv( B iv[8] ) { memcpy(iv,"S20m\0\0\0\0",8); X4U( iv+4, (time(0)-(77<<24))*5 ); }
U analyze_iv( B iv[8], time_t* t ) { *t = U4B(iv+4)/5+(77<<24); return !memcmp(iv,"S20m",4); }

int main( int ac, char* av[] ) __
  #define BUF_SZ (64*160000) /* 10.24 MB */
  #define SHA_SZ 32
  FILE* fo=0; int n; B iv[8]; B k[32]; U c,m; struct timeb t0,t1;
  if( test()!=0 ) exit(1); /* self-test, quite fast so it can be always present */
  if( ac<=4 || !(av[1][0]=='e'||av[1][0]=='d') || av[1][1]!='\0' )
    printf("Syntax: salsa20 e|d key|- input-file output-file\n"), exit(0);
  if( strcmp(av[2],"-")==0 ) __ char pwd[300]={'\0'};
    printf("Enter password: "); fgets(pwd,sizeof(pwd),stdin);
     U l=strlen(pwd); if( l>0 && pwd[l-1]=='\x0A' ) --l; if( l==0 ) exit(0);
    mrm256( k, pwd, l ); _
  else mrm256( k, av[2], strlen(av[2]) );
  FILE* fi = fopen(av[3],"rb"); if(!fi) printf("No file %s\n",av[3]), exit(2);
  B* data = malloc( BUF_SZ ); ftime(&t0);
  if( av[1][0]=='e' ) __
    n = fread( data+SHA_SZ, 1, BUF_SZ-SHA_SZ, fi ); m = n;
    mrm256( data, data+SHA_SZ, n );
    generate_iv( iv );
    c = salsa20( data, k, iv, 0, (SHA_SZ+n+63)/64 );
    fo = fopen(av[4],"wb"); if(!fo) printf("Can't make %s\n",av[4]), fclose(fi), exit(3);
    fwrite( iv, 1, 8, fo );
    fwrite( data, 1, SHA_SZ+n, fo );
    for( n = fread( data, 1, BUF_SZ, fi ); n!=0; n = fread( data, 1, BUF_SZ, fi )) __
      c = salsa20( data, k, iv, c, (n+63)/64 );
      m += fwrite( data, 1, n, fo ); _ _
  else __ struct tm ts; char tf[20]; time_t t;
    #define ERR(s,k) printf("%s\n",s), fclose(fi), exit(k)
    n = fread( iv, 1, 8, fi ); if( n<8 ) ERR("Too short file",4);
    if( !analyze_iv( iv, &t ) ) ERR("No signature",5);
    n = fread( data, 1, BUF_SZ, fi ); if( n<SHA_SZ ) ERR("Too short file",6);
    c = salsa20( data, k, iv, 0, (n+63)/64 );
    B sha[SHA_SZ]; mrm256( sha, data+SHA_SZ, n-SHA_SZ );
    if( memcmp(data,sha,SHA_SZ) != 0 ) ERR("Wrong password/corrupted data",7);
    ts=*localtime(&t); strftime(tf,sizeof(tf),"%Y.%m.%d %H:%M:%S",&ts);
    printf("OK, was encrypted: %s\n",tf);
    fo = fopen(av[4],"wb"); if(!fo) printf("Can't make %s\n",av[4]), fclose(fi), exit(8);
    m = fwrite( data+SHA_SZ, 1, n-SHA_SZ, fo );
    for( n = fread( data, 1, BUF_SZ, fi ); n!=0; n = fread( data, 1, BUF_SZ, fi )) __
      c = salsa20( data, k, iv, c, (n+63)/64 );
      m += fwrite( data, 1, n, fo ); _ _
  free(data); ftime(&t1);
  fclose( fo ); fclose( fi );
  double tt = t1.time-t0.time + (t1.millitm-t0.millitm)/1e3; if(tt==0.0) tt=0.001;
  printf("%.1f s, %.1f MB/s", tt, m/1e6/tt); /* i3-3220 3.3GHz: 290 MB/s, i3-4160 3.6: 384 */
  return 0; _

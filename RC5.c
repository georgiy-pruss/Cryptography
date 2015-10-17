/* RC5REF.C -- Reference implementation of RC5-32/12/16 in C. */
/* Copyright (C) 1995 RSA Data Security, Inc. */

/* Modified by G.Pruss mas.orgfree.com 2015 */
/*
cygwin64: gcc -O2 [-m64] RC5.c -o rc5-cw.exe
msvc32: vcvarsall.bat x86   && cl /nologo /O2 RC5.c /Fe"rc5-vc.exe"
msvc64: vcvarsall.bat amd64 && cl /nologo /O2 RC5.c /Fe"rc5-vc64.exe"
lnx64: gcc [-m64] -O2 RC5.c -o rc5-lnx
sol32: cc -m32 -D_B_E_ -O2 RC5.c -o rc5-sol
sol64: cc -m64 -D_B_E_ -O2 RC5.c -o rc5-sol64
aix32: xlc -q32 -D_B_E_ -O2 RC5.c -o rc5-aix
aix64: xlc -q64 -D_B_E_ -O2 RC5.c -o rc5-aix64
*/

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#ifdef _MSC_VER
#define unlink(s) _unlink(s)
#else
#include <unistd.h>
#endif

#define __ {
#define _  }

typedef unsigned char       BYTE;
typedef unsigned int        U32; /* these definitions are */
typedef unsigned long long  U64; /* true on all platforms */

#define W 32 /* word size in bits */
#define V  4 /* word size in bytes */
#define U  8 /* block size in bytes */
#define P 0xb7e15163u
#define Q 0x9e3779b9u

#define WX 64 /* word size in bits */
#define VX  8 /* word size in bytes */
#define UX 16 /* block size in bytes */
#define PX 0xB7E151628AED2A6Bull
#define QX 0x9E3779B97F4A7C15ull

typedef struct G __ /* RC5 control block */
  int R; /* number of rounds */
  int B; /* number of bytes in key */
  int C; /* number  words in key = ceil(8*B/W) */
  int T; /* size of table S = 2*(R+1) words */
  U32* S; /* expanded key table S[T] (U64* in WX mode) */
  BYTE* K; /* key K[B] */ _ G;

/* Rotation operators. x must be unsigned, to get logical right shift*/
#define ROTL(x,y)  (((x)<<((y)&(W-1)))|((x)>>(W-((y)&(W-1)))))
#define ROTR(x,y)  (((x)>>((y)&(W-1)))|((x)<<(W-((y)&(W-1)))))
#define ROTLX(x,y) (((x)<<((y)&(WX-1)))|((x)>>(WX-((y)&(WX-1)))))
#define ROTRX(x,y) (((x)>>((y)&(WX-1)))|((x)<<(WX-((y)&(WX-1)))))

#ifdef _B_E_ /* Define for Solaris Sparc or AIX PowerPC */
#define FLIP(x) ((x>>24)|((x&0x00ff0000)>>8)|((x&0x0000ff00)<<8)|(x<<24))
#define FLIP2(xx) xx[0]=FLIP(xx[0]); xx[1]=FLIP(xx[1])
#define FLIPX(x) (        (x>>56)|(x<<56)| \
  ((x&0x00ff000000000000ull)>>40)|((x&0x000000000000ff00ull)<<40)| \
  ((x&0x0000ff0000000000ull)>>24)|((x&0x0000000000ff0000ull)<<24)| \
  ((x&0x000000ff00000000ull)>> 8)|((x&0x00000000ff000000ull)<< 8))
#define FLIP2X(xx) xx[0]=FLIPX(xx[0]); xx[1]=FLIPX(xx[1])
#else /* default is little-endian */
#define FLIP(x) (x)
#define FLIP2(xx) /*nothing*/
#define FLIPX(x) (x)
#define FLIP2X(xx) /*nothing*/
#endif

void RC5_SETUP( G* g, int R, int B, BYTE* K ) __ /* key K[0...B-1] */
  int i, C, T, M; U32 a, b; U32* L; /* L[C] */  U32* S; /* S[T] */
  g->R = R; g->B = B; g->K = (BYTE*)malloc(B);  memcpy(g->K,K,B);
  g->C = C = (8*B + (W-1))/W; /* ceil(8*B/W) */ L = (U32*)malloc(V*C);
  g->T = T = 2*(R+1);                           S = (U32*)malloc(V*T);
  /* Initialize L, then S, then mix key into S */
  for(i=B-1,L[C-1]=0; i!=-1; --i) L[i/V] = (L[i/V]<<8) + K[i];
  for(S[0]=P,i=1; i<T; ++i) S[i] = S[i-1]+Q;
  for(a=b=i=0, M=T>C?T:C; i<3*M; ++i) __
    a = S[i%T] = ROTL(S[i%T]+a+b,3); b = L[i%C] = ROTL(L[i%C]+a+b,a+b); _
  g->S = S; free(L); _

void RC5X_SETUP( G* g, int R, int B, BYTE* K ) __ /* key K[0...B-1] */
  int i, C, T, M; U64 a, b; U64* L; /* L[C] */  U64* S; /* S[T] */
  g->R = R; g->B = B; g->K = (BYTE*)malloc(B);  memcpy(g->K,K,B);
  g->C = C = (8*B + (WX-1))/WX; /* ceil(8*B/WX) */ L = (U64*)malloc(VX*C);
  g->T = T = 2*(R+1);                              S = (U64*)malloc(VX*T);
  /* Initialize L, then S, then mix key into S */
  for(i=B-1,L[C-1]=0; i!=-1; --i) L[i/VX] = (L[i/VX]<<8) + K[i];
  for(S[0]=PX,i=1; i<T; ++i) S[i] = S[i-1]+QX;
  for(a=b=i=0, M=T>C?T:C; i<3*M; ++i) __
    a = S[i%T] = ROTLX(S[i%T]+a+b,3); b = L[i%C] = ROTLX(L[i%C]+a+b,a+b); _
  g->S = (U32*)S; free(L); _

void RC5_FREE(G* g) { free(g->K); free(g->S); g->K=0; g->S=0; }

void RC5_ENCRYPT( G* g, U32* pt, U32* ct ) __ /* 2 U32 input pt/output ct */
  int i, n=g->R; U32* S=g->S; U32 a=pt[0]+S[0], b=pt[1]+S[1];
  for(i=1; i<=n; ++i) { a = ROTL(a^b,b)+S[2*i]; b = ROTL(b^a,a)+S[2*i+1]; }
  ct[0]=a; ct[1]=b; _

void RC5X_ENCRYPT( G* g, U64* pt, U64* ct ) __ /* 2 U64 input pt/output ct */
  int i, n=g->R; U64* S=(U64*)g->S; U64 a=pt[0]+S[0], b=pt[1]+S[1];
  for(i=1; i<=n; ++i) { a = ROTLX(a^b,b)+S[2*i]; b = ROTLX(b^a,a)+S[2*i+1]; }
  ct[0]=a; ct[1]=b; _

void RC5_DECRYPT( G* g, U32* ct, U32* pt ) __ /* 2 U32 input ct/output pt */
  int i; U32* S=g->S; U32 b=ct[1], a=ct[0];
  for(i=g->R; i>0; --i) { b = ROTR(b-S[2*i+1],a)^a; a = ROTR(a-S[2*i],b)^b; }
  pt[1]=b-S[1]; pt[0]=a-S[0]; _

void RC5X_DECRYPT( G* g, U64* ct, U64* pt ) __ /* 2 U64 input ct/output pt */
  int i; U64* S=(U64*)g->S; U64 b=ct[1], a=ct[0];
  for(i=g->R; i>0; --i) { b = ROTRX(b-S[2*i+1],a)^a; a = ROTRX(a-S[2*i],b)^b; }
  pt[1]=b-S[1]; pt[0]=a-S[0]; _

typedef struct O { int r, b, ext, decr, cln; time_t start;
  char* pwd; char* in; char* out; FILE* fi; FILE* fo; } O;

void show_opts(const O* o) __
  printf( "o_decr=%d  o_cln=%d  o_ext=%d  o_r=%d  o_b=%d\npwd='%s'  in='%s'  out='%s'\n",
  o->decr, o->cln, o->ext, o->r, o->b, o->pwd, o->in, o->out ); _

#define RC5SGN  0x354352
#define RC5XSGN 0x356372

U64 encrypt_file( O* o ) __
  G g; int n,d, more; U64 sz=0; U32 header[2], cnt=0;
  header[0] = (o->r<<24)|(o->ext?RC5XSGN:RC5SGN); header[1] = (U32)o->start;
  FLIP2(header); fwrite( header, 1, U, o->fo ); FLIP2(header);
  if( o->ext ) __
    U64 ti[2], to[2];
    RC5X_SETUP(&g,o->r,o->b,(BYTE*)o->pwd);
    for(more=1;more;) __
      n = fread( ti, 1, UX, o->fi ); d = UX-n; sz += n;
      if( d>0 ) memset( (char*)ti+n, d, d ), more=0;
      FLIP2X(ti); ti[0]^=++cnt; ti[1]^=header[1]; RC5X_ENCRYPT(&g,ti,to); FLIP2X(to);
      fwrite( to, 1, UX, o->fo ); _ _
  else __
    U32 ti[2], to[2];
    RC5_SETUP(&g,o->r,o->b,(BYTE*)o->pwd);
    for(more=1;more;) __
      n = fread( ti, 1, U, o->fi ); d = U-n; sz += n;
      if( d>0 ) memset( (char*)ti+n, d, d ), more=0;
      FLIP2(ti); ti[0]^=++cnt; ti[1]^=header[1]; RC5_ENCRYPT(&g,ti,to); FLIP2(to);
      fwrite( to, 1, U, o->fo ); _ _
  return sz; _

U64 decrypt_file( O* o ) __
  #define EXIT(m,n) printf(m), fclose(o->fi), fclose(o->fo), unlink(o->out), exit(n)
  U32 header[2], cnt=0; U64 sz=U; int d, n; G g;
  if( fread( header, 1, U, o->fi ) != U ) EXIT("Too short file\n", 10);
  FLIP2(header); o->r = header[0]>>24;
  if( (header[0]&0xFFFFFF)==RC5XSGN ) __
    U64 ti[2], to[2];
    RC5X_SETUP(&g,o->r,o->b,(BYTE*)o->pwd);
    for(d=0;;d=1) __
      n = fread( ti, 1, UX, o->fi ); sz += n;
      if( n==0 ) __
        d = ((BYTE*)to)[UX-1]; if( d>UX ) EXIT("Not RC5 file.\n", 12);
        fwrite( to, 1, UX-d, o->fo ); break; _
      if( n!=UX ) EXIT("Not RC5 file!\n", 13);
      if(d) fwrite( to, 1, UX, o->fo );
      FLIP2X(ti); RC5X_DECRYPT(&g,ti,to); to[0]^=++cnt; to[1]^=header[1]; FLIP2X(to); _ _
  else if( (header[0]&0xFFFFFF)==RC5SGN ) __
    U32 ti[2], to[2];
    RC5_SETUP(&g,o->r,o->b,(BYTE*)o->pwd);
    for(d=0;;d=1) __
      n = fread( ti, 1, U, o->fi ); sz += n;
      if( n==0 ) __
        d = ((BYTE*)to)[U-1]; if( d>U ) EXIT("Not RC5 file.\n", 12);
        fwrite( to, 1, U-d, o->fo ); break; _
      if( n!=U ) EXIT("Not RC5 file!\n", 13);
      if(d) fwrite( to, 1, U, o->fo );
      FLIP2(ti); RC5_DECRYPT(&g,ti,to); to[0]^=++cnt; to[1]^=header[1]; FLIP2(to); _ _
  else EXIT("Not RC5 file\n", 11);
  return sz; _

struct { char* key; U32 pt[2]; U32 ct[2]; } kpc[] = __
  __"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    {0x00000000,0x00000000}, {0xEEDBA521,0x6D8F4B15} _,
  __"\x91\x5F\x46\x19\xBE\x41\xB2\x51\x63\x55\xA5\x01\x10\xA9\xCE\x91",
    {0xEEDBA521,0x6D8F4B15}, {0xAC13C0F7,0x52892B5B} _,
  __"\x78\x33\x48\xE7\x5A\xEB\x0F\x2F\xD7\xB1\x69\xBB\x8D\xC1\x67\x87",
    {0xAC13C0F7,0x52892B5B}, {0xB7B3422F,0x92FC6903} _,
  __"\xDC\x49\xDB\x13\x75\xA5\x58\x4F\x64\x85\xB4\x13\xB5\xF1\x2B\xAF",
    {0xB7B3422F,0x92FC6903}, {0xB278C165,0xCC97D184} _,
  __"\x52\x69\xF1\x49\xD4\x1B\xA0\x15\x24\x97\x57\x4D\x7F\x15\x31\x25",
    {0xB278C165,0xCC97D184}, {0x15E444EB,0x249831DA} _ _;

void test( char* arg ) __
  int i; G g;
  if( sizeof(U32)!=V || sizeof(U64)!=VX )
    printf("Data size! %d %d\n",sizeof(U32),sizeof(U64)), exit(1);
  for(i=0;i<sizeof(kpc)/sizeof(kpc[0]);++i) __
    U32 pt1[2], pt2[2], ct[2];
    BYTE key[16];
    memcpy(key,kpc[i].key,sizeof(key));
    pt1[0]=kpc[i].pt[0]; pt1[1]=kpc[i].pt[1];
    RC5_SETUP(&g, 12, sizeof(key), key);
    RC5_ENCRYPT(&g,pt1,ct);
    if(ct[0]!=kpc[i].ct[0] || ct[1]!=kpc[i].ct[1])
      printf("Encryption Error!\n"), exit(2);
    RC5_DECRYPT(&g,ct,pt2);
    if(pt1[0]!=pt2[0] || pt1[1]!=pt2[1])
      printf("Decryption Error!\n"), exit(3);
    RC5_FREE(&g); _
  for(i=0;i<256;++i) __ /* test some 64-bit encoding/decoding */
    U64 pt1[2], pt2[2], ct[2];
    BYTE key[64]; memset(key,i,sizeof(key));
    RC5X_SETUP(&g, 4+i/2, sizeof(key), key);
    pt1[0] = 0x1122334455667788ull; pt1[1] = 0x99AABBCCDDEEFF00ull;
    RC5X_ENCRYPT(&g,pt1,ct);
    RC5X_DECRYPT(&g,ct,pt2);
    if(pt1[0]!=pt2[0] || pt1[1]!=pt2[1])
      printf("64 Decryption Error!\n");
    RC5_FREE(&g); _
  if( arg ) __ /* pwd;cf1:pf1;cf2[:pf2];... must end with ';'! */
    char* b; char* e; char*p, cf[260],pf[260]="",pwd[260],b1[512],b2[512];
    for( b=arg; b && (e=strchr(b,';')); b=e+1 ) __  int n1,n2,sz; O o={12,16,0};
      p=strchr(b,':');
      if( p && p<e ) __
        memcpy(cf,b,p-b);cf[p-b]='\0'; memcpy(pf,p+1,e-p-1);pf[e-p-1]='\0'; _
      else __
        memcpy(cf,b,e-b);cf[e-b]='\0'; if(!pf[0]) { strcpy(pwd,cf); continue; } _
      /* decrypt cf to tmp; compare pf and tmp; remove tmp */
      o.in = cf; o.out = "#tmp#"; o.pwd = strdup(pwd); o.b = strlen(o.pwd);
      o.fi = fopen( o.in, "rb" ); o.fo = fopen( o.out, "wb" );
      if(!o.fi) { printf("No file %s\n",o.in); continue; }
      decrypt_file( &o ); fclose( o.fi ); fclose( o.fo );
      o.fi = fopen( pf, "rb" ); o.fo = fopen( o.out, "rb" );
      if(!o.fi) { printf("No file %s\n",pf); continue; }
      for(sz=0;;sz+=n1) __
        n1 = fread( b1, 1, sizeof(b1), o.fi );
        n2 = fread( b2, 1, sizeof(b2), o.fo ); if( n1==0 && n2==0 ) break;
        if( n1!=n2 ) { printf("Different length: %d %d %s\n",n1,n2,cf); break; }
        if( memcmp(b1,b2,n1)!=0 ) { printf("Different contents: %s\n",cf); break; } _
      fclose( o.fi ); fclose( o.fo );
      unlink(o.out); _ _ _

#define SYNTAX "rc5.exe [options]... infile outfile\n" \
  "  -d      decrypt (and options -x and -r are ignored)\n" \
  "  -e      encrypt (default)\n" \
  "  -x      use 16-byte blocks; default is 8-byte blocks\n" \
  "  -r n    set number of rounds, e.g. 12 or 16; can be 0..255\n" \
  "  -p pwd  specify password (1..255), default - enter interactively\n" \
  "infile and outfile can be streams, e.g. console\n"

int main( int ac, char* av[] ) __
  if( ac>=3 ) __ /* [opts]... file1 file2 */
    int i; time_t t0,t1; U64 sz; O o={12,16,0}; /* r,b,ext */
    for( i=1; i<ac && av[i][0]=='-' && av[i][2]=='\0'; ++i )
      switch( av[i][1] ) __
        case 'd': o.decr=1; break;
        case 'e': o.decr=0; break;
        case 'x': o.ext=1; break;
        case 'r': if(i+1<ac) o.r=atoi(av[++i]); /* 0..255 */ break;
        case 'p': if(i+1<ac) o.pwd=strdup(av[++i]); break;
        default: printf("Unknown option '%c'\n",av[i][1]); _
    if( o.r<0 || o.r>255 || i!=ac-2 ) printf("%s",SYNTAX), exit(4);
    o.in=av[i]; o.out=av[i+1];
    if( !o.pwd ) __
      int n; char pwd[256]={0};
      printf("Enter password: "); fgets(pwd,sizeof(pwd),stdin); n=strlen(pwd);
      if( n>0 && pwd[n-1]=='\x0A' ) pwd[n-1]='\0';
      if( strlen(pwd)==0 ) exit(0);
      o.pwd = strdup(pwd); _
    o.b = strlen(o.pwd); /* show_opts(&o); */
    __ char tm[30] = "";
      o.fi = fopen( o.in, "rb" );
      if( !o.fi ) printf( "No file '%s'\n", o.in ), exit(5);
      o.fo = fopen( o.out, "wb" );
      if( !o.fo ) printf( "Can't create '%s'\n", o.out ), fclose(o.fi), exit(6);
      /* Finally! Time and do encrypt/decrypt */
      time(&t0); o.start = t0; /* used as "salt" for encryption */
      sz = o.decr ? decrypt_file( &o ) : encrypt_file( &o );
      time(&t1);
      fclose( o.fi ); fclose( o.fo );
      if(t1!=t0) sprintf( tm, ", %ld s, %llu kB/s", (long)t1-t0, sz/((t1-t0)*1000) );
      printf( "%llu bytes%s\n", sz, tm ); _
    free( o.pwd ); _
  else
    test( ac>1 ? av[1] : 0 );
    if( ac==1 || !strcmp(av[1],"-h") || !strcmp(av[1],"--help") ) printf(SYNTAX);
  return 0; _

/* with 40-char password; 1GB file
rounds:        16   32   48   64   128  255
cygwin 64      24.5 20.5 17.5 15.5 10.5 6.5 MB/s
cygwin 64 -x   47.5 40.0 34.5 31.0 21.0 13
msvc   64      64.3 51.4 42.8 36.7 23.0 13
msvc   64 -x   102  85   73   64   42   25
@ Win 7; i3 3220 3.3GHz 8GB */

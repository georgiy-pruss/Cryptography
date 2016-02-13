// Speck 128/128
// https://github.com/dimview/speck_cipher
// http://habrahabr.ru/post/271435/
// https://en.wikipedia.org/wiki/Speck_%28cipher%29

#include <stdio.h>
#include <inttypes.h>

#define ROUNDS 32

static inline void
speck_round( uint64_t& x, uint64_t& y, const uint64_t k )
{
  x = (x >> 8) | (x << (8 * sizeof(x) - 8)); // x = ROTR(x, 8)
  x += y;
  x ^= k;
  y = (y << 3) | (y >> (8 * sizeof(y) - 3)); // y = ROTL(y, 3)
  y ^= x;
}

// Generate key schedule and encrypt at the same time
void
speck_encrypt( const uint64_t plaintext[2], const uint64_t key[2], /* OUT */ uint64_t ciphertext[2] )
{
  uint64_t b = key[0];
  uint64_t a = key[1];
  uint64_t y = plaintext[0];
  uint64_t x = plaintext[1];
  for( unsigned i = 0; i < ROUNDS; ++i )
  {
    speck_round( x, y, b );
    speck_round( a, b, i ); // Get next row of key schedule
  }
  ciphertext[0] = y;
  ciphertext[1] = x;
}

int
main(void)
{
  uint64_t plaintext[2] = {0x7469206564616d20ULL, 0x6c61766975716520ULL};
  uint64_t key[2] = {0x0706050403020100ULL, 0x0f0e0d0c0b0a0908ULL};
  uint64_t ciphertext[2];

  speck_encrypt( plaintext, key, /* OUT */ ciphertext );

  printf("Plaintext:  0x%016llx 0x%016llx\n", plaintext[0],  plaintext[1]);
  printf("Key:        0x%016llx 0x%016llx\n", key[0],        key[1]);
  printf("Ciphertext: 0x%016llx 0x%016llx\n", ciphertext[0], ciphertext[1]);
  printf("Expected:   0x7860fedf5c570d18 0xa65d985179783265\n\n");

  return 0;
}

/*
Block size (bits, bytes)  Key size (bits, bytes)  Rounds

2×16 =  32  4   4×16 =  64  8   22

2×24 =  48  6   3×24 =  72  9   22
                4×24 =  96 12   23

2×32 =  64  8   3×32 =  96 12   26
                4×32 = 128 16   27

2×48 =  96 12   2×48 =  96 12   28
                3×48 = 144 18   29

2×64 = 128 16   2×64 = 128 16   32  *
                3×64 = 192 24   33
                4×64 = 256 32   34

http://eprint.iacr.org/2013/404
http://eprint.iacr.org/2013/568
http://eprint.iacr.org/2014/320
https://www.schneier.com/blog/archives/2013/07/simon_and_speck.html
https://github.com/raullenchai/ciphers
*/

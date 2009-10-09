
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "tests/malloc.h"
#include <string.h>

typedef  unsigned char  V128[16];
typedef  unsigned char  V64[8];
typedef  unsigned int   UInt;
typedef  signed int     Int;
typedef  unsigned char  UChar;

static UChar randUChar ( void )
{
   static UInt seed = 80021;
   seed = 1103515245 * seed + 12345;
   return (seed >> 17) & 0xFF;
}

static void randV128 ( V128* v )
{
   Int i;
   for (i = 0; i < 16; i++)
      (*v)[i] = randUChar();
}

static void randV64 ( V64* v )
{
   Int i;
   for (i = 0; i < 8; i++)
      (*v)[i] = randUChar();
}

static void showV128 ( V128* v )
{
   Int i;
   for (i = 0; i < 16; i++)
      printf("%02x", (Int)(*v)[i]);
}

static void showV64 ( V64* v )
{
   Int i;
   for (i = 0; i < 8; i++)
      printf("%02x", (Int)(*v)[i]);
}

UInt do_pmovmskb_xmm_r32 ( V128* arg )
{
   UInt res;
   __asm__ __volatile__(
      "movupd  (%1), %%xmm1"     "\n\t"
      "pmovmskb %%xmm1, %0"      "\n"
      : /*out*/ "=r"(res) : /*in*/ "r"(arg)
                          : /*trash*/"memory","xmm1"
   );
   return res;
}

UInt do_pmovmskb_mmx_r32 ( V64* arg )
{
   UInt res;
   __asm__ __volatile__(
      "movq  (%1), %%mm1"     "\n\t"
      "pmovmskb %%mm1, %0"      "\n"
      : /*out*/ "=r"(res) : /*in*/ "r"(arg)
                          : /*trash*/"memory","mm1"
   );
   return res;
}

int main ( void )
{
   V128 argL;
   V64 argS;
   UInt res, i;
   UChar* undef = malloc(1);
   for (i = 0; i < 10; i++) {
     randV128( &argL );
     //if (i == 9) argL[5] = *undef;
     res = do_pmovmskb_xmm_r32( &argL );
     showV128( &argL );
     printf("  %08x\n", res );
   }
   for (i = 0; i < 10; i++) {
     randV64( &argS );
     res = do_pmovmskb_mmx_r32( &argS );
     showV64( &argS );
     printf("  %08x\n", res );
   }
   free(undef);
   return 0;
}

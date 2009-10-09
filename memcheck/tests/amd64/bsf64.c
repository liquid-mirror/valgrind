
/* What this program does: checks memcheck's handling of 64-, 32- and
   16-bit count trailing zeroes (Ctz64, Ctz32, Ctz16). */

#include <stdio.h>
#include "../../memcheck.h"

typedef  unsigned long long int  ULong;
typedef  unsigned int            UInt;
typedef  unsigned short          UShort;


/* Return X, but mark as undefined all bits in it which are 1 in NOTV.
   (note this is the opposite of the V bits encoding used
   internally). */
ULong undef64 ( ULong x, ULong notv )
{
   ULong allzeroes = 0;
   VALGRIND_MAKE_MEM_UNDEFINED(&allzeroes, sizeof(allzeroes));
   // now allzeroes is all 0s and all undefined
   allzeroes &= notv;
   // now allzeroes is still all 0s, but the places where notv is
   // zero are now defined

   // this doesn't change the value of x.  But it 'infect' the 
   // relevant bit positions, making them undefined.
   x ^= allzeroes;
   return x;
}

ULong ctz64 ( ULong x )
{
   ULong res;
   __asm__ __volatile__( "bsfq %1, %0" : "=b"(res) : "a"(x) : "cc" );
   return res;
}

ULong ctz32 ( ULong x )
{
   UInt res;
   __asm__ __volatile__( "bsfl %1, %0" : "=b"(res) : "a"((UInt)x) : "cc" );
   return (ULong)res;
}

ULong ctz16 ( ULong x )
{
   UShort res;
   __asm__ __volatile__( "bsfw %1, %0" : "=b"(res) : "a"((UShort)x) : "cc" );
   return (ULong)res;
}


void try64 ( ULong expect_err, ULong x, ULong notv )
{
  // x, notv: clean
  ULong xbad = undef64(x, notv);
  // xbad: partially undefined as per notv
  ULong res = ctz64(xbad);
  // res: possibly undefined, as per ctz interpretation of xbad
  ULong resclean = res;
  VALGRIND_MAKE_MEM_DEFINED(&resclean, sizeof(resclean));
  if (expect_err)
     fprintf(stderr, "Expect: ERROR\n");
  else
     fprintf(stderr, "Expect: no error\n");
  VALGRIND_CHECK_VALUE_IS_DEFINED(res);
  fprintf(stderr, "ctz64 ( arg=0x%016llx, undefbits=0x%016llx ) = %d\n",
          x, notv, resclean);
  fprintf(stderr, "\n");
}



void try32 ( ULong expect_err, ULong x, ULong notv )
{
  // x, notv: clean
  ULong xbad = undef64(x, notv);
  // xbad: partially undefined as per notv
  ULong res = ctz64( xbad & 0xFFFFFFFFULL );
  // res: possibly undefined, as per ctz interpretation of xbad
  ULong resclean = res;
  VALGRIND_MAKE_MEM_DEFINED(&resclean, sizeof(resclean));
  if (expect_err)
     fprintf(stderr, "Expect: ERROR\n");
  else
     fprintf(stderr, "Expect: no error\n");
  VALGRIND_CHECK_VALUE_IS_DEFINED(res);
  fprintf(stderr, "ctz32 ( arg=0x%016llx, undefbits=0x%016llx ) = %d\n",
          x, notv, resclean);
  fprintf(stderr, "\n");
}


void try16 ( ULong expect_err, ULong x, ULong notv )
{
  // x, notv: clean
  ULong xbad = undef64(x, notv);
  // xbad: partially undefined as per notv
  ULong res = ctz16(xbad & 0xFFFFULL);
  // res: possibly undefined, as per ctz interpretation of xbad
  ULong resclean = res;
  VALGRIND_MAKE_MEM_DEFINED(&resclean, sizeof(resclean));
  if (expect_err)
     fprintf(stderr, "Expect: ERROR\n");
  else
     fprintf(stderr, "Expect: no error\n");
  VALGRIND_CHECK_VALUE_IS_DEFINED(res);
  fprintf(stderr, "ctz16 ( arg=0x%016llx, undefbits=0x%016llx ) = %d\n",
          x, notv, resclean);
  fprintf(stderr, "\n");
}


int main ( void )
{
  fprintf(stderr, "\n");

  fprintf(stderr, "======== 64-bit cases ========\n\n");

  //   err?   ctz-arg   badbits
  try64( 0,     0x10,     0 );
  try64( 1,     0x10,     1 );
  try64( 1,     0x10,     2 );
  try64( 1,     0x10,     4 );
  try64( 1,     0x10,     8 );
  try64( 1,     0x10,     0x10 );
  try64( 0,     0x10,     0x20 );
  try64( 0,     0x10,     0x40 );
  try64( 0,     0x10,     0x80 );
  try64( 0,     0x10,     0x4000000000000000ULL );
  try64( 0,     0x10,     0x8000000000000000ULL);

  try64( 0,     0,          0 );
  try64( 1,     0,          2 );
  try64( 1,     0,          0x8000000000000000ULL);
  try64( 0,     0x4000000000000000ULL, 0x8000000000000000ULL);
  try64( 1,     0x4000000000000000ULL, 0x8001000000000000ULL);

  try64( 0,     0xFFFFFFFFFFFFFFFFULL, 0 );
  try64( 0,     0xFFFFFFFFFFFFFFFFULL, 2 );

  try64( 0,     0xFFFFFFFFFFFFFFFEULL, 0 );
  try64( 1,     0xFFFFFFFFFFFFFFFEULL, 1 );
  try64( 1,     0xFFFFFFFFFFFFFFFEULL, 2 );
  try64( 0,     0xFFFFFFFFFFFFFFFEULL, 4 );

  fprintf(stderr, "======== 32-bit cases ========\n\n");

  //   err?   ctz-arg   badbits
  try32( 0,     0x10,     0 );
  try32( 1,     0x10,     1 );
  try32( 1,     0x10,     2 );
  try32( 1,     0x10,     4 );
  try32( 1,     0x10,     8 );
  try32( 1,     0x10,     0x10 );
  try32( 0,     0x10,     0x20 );
  try32( 0,     0x10,     0x40 );
  try32( 0,     0x10,     0x80 );
  try32( 0,     0x10,     0x40000000 );
  try32( 0,     0x10,     0x80000000 );

  fprintf(stderr, "======== 16-bit cases ========\n\n");

  //   err?   ctz-arg   badbits
  try16( 0,     0x10,     0 );
  try16( 1,     0x10,     1 );
  try16( 1,     0x10,     2 );
  try16( 1,     0x10,     4 );
  try16( 1,     0x10,     8 );
  try16( 1,     0x10,     0x10 );
  try16( 0,     0x10,     0x20 );
  try16( 0,     0x10,     0x40 );
  try16( 0,     0x10,     0x80 );
  try16( 0,     0x10,     0x4000 );
  try16( 0,     0x10,     0x8000 );

  try16( 0,     0x10,     0x10000 );

  return 0;
}

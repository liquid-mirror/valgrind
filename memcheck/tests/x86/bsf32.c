
/* What this program does: checks memcheck's handling of 32- and
   16-bit count trailing zeroes (Ctz32, Ctz16). */

#include <stdio.h>
#include "../../memcheck.h"

typedef  unsigned int  UInt;

/* Return X, but mark as undefined all bits in it which are 1 in NOTV.
   (note this is the opposite of the V bits encoding used
   internally). */
UInt undef32 ( UInt x, UInt notv )
{
   UInt allzeroes = 0;
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

UInt ctz32 ( UInt x )
{
   UInt res;
   __asm__ __volatile__( "bsfl %1, %0" : "=b"(res) : "a"(x) : "cc" );
   return res;
}

UInt ctz16 ( UInt x )
{
   unsigned short res;
   __asm__ __volatile__( "bsfw %1, %0" : "=b"(res) : "a"((unsigned short)x) : "cc" );
   return (UInt)res;
}

void try32 ( UInt expect_err, UInt x, UInt notv )
{
  // x, notv: clean
  UInt xbad = undef32(x, notv);
  // xbad: partially undefined as per notv
  UInt res = ctz32(xbad);
  // res: possibly undefined, as per ctz interpretation of xbad
  UInt resclean = res;
  VALGRIND_MAKE_MEM_DEFINED(&resclean, sizeof(resclean));
  if (expect_err)
     fprintf(stderr, "Expect: ERROR\n");
  else
     fprintf(stderr, "Expect: no error\n");
  VALGRIND_CHECK_VALUE_IS_DEFINED(res);
  fprintf(stderr, "ctz32 ( arg=0x%08x, undefbits=0x%08x ) = %d\n",
          x, notv, resclean);
  fprintf(stderr, "\n");
}


void try16 ( UInt expect_err, UInt x, UInt notv )
{
  // x, notv: clean
  UInt xbad = undef32(x, notv);
  // xbad: partially undefined as per notv
  UInt res = ctz16(xbad & 0xFFFF);
  // res: possibly undefined, as per ctz interpretation of xbad
  UInt resclean = res;
  VALGRIND_MAKE_MEM_DEFINED(&resclean, sizeof(resclean));
  if (expect_err)
     fprintf(stderr, "Expect: ERROR\n");
  else
     fprintf(stderr, "Expect: no error\n");
  VALGRIND_CHECK_VALUE_IS_DEFINED(res);
  fprintf(stderr, "ctz16 ( arg=0x%08x, undefbits=0x%08x ) = %d\n",
          x, notv, resclean);
  fprintf(stderr, "\n");
}


int main ( void )
{
  fprintf(stderr, "\n");

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

  try32( 0,     0,          0 );
  try32( 1,     0,          2 );
  try32( 1,     0,          0x80000000 );
  try32( 0,     0x40000000, 0x80000000 );
  try32( 1,     0x40000000, 0x80010000 );

  try32( 0,     0xFFFFFFFF, 0 );
  try32( 0,     0xFFFFFFFF, 2 );

  try32( 0,     0xFFFFFFFE, 0 );
  try32( 1,     0xFFFFFFFE, 1 );
  try32( 1,     0xFFFFFFFE, 2 );
  try32( 0,     0xFFFFFFFE, 4 );

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

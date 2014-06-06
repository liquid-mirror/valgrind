
#include <stdio.h>
#include <string.h>
#include <assert.h>

#define IS_32_ALIGNED(_ptr)  (0 == (31 & ((unsigned long int)(_ptr))))

typedef  unsigned long long int  ULong;
typedef  unsigned char           UChar;

ULong arr[100];

ULong clone8 ( int x )
{
  ULong r = x & 0xF;
  r |= (r << 4);
  r |= (r << 8);
  r |= (r << 16);
  r |= (r << 32);
  return r;
}

// unchecked load
__attribute__((noinline))
void do_xfer_unchecked_s_d ( UChar* src, UChar* dst )
{
  __asm__ __volatile__(
    "qvlfdx  15,0,%0 ; qvstfdx 15,0,%1"
    : /*OUT*/
    : /*IN*/"r"(src), "r"(dst)
    : "memory"
  );
}

// checked load
__attribute__((noinline))
void do_xfer_checked_s_d ( UChar* src, UChar* dst )
{
  __asm__ __volatile__(
    "qvlfdxa  15,0,%0 ; qvstfdxa 15,0,%1"
    : /*OUT*/
    : /*IN*/"r"(src), "r"(dst)
    : "memory"
  );
}



int main ( void )
{
  memset(arr, 0xAA, sizeof(arr));

  int bi = 0;
  ULong* pi = NULL;

  while (1) {
    pi = &arr[bi];
    if (IS_32_ALIGNED(pi)) break;
    bi++;
  }

  printf("bi = %d  pi = %p\n", bi, pi);

  int i;
  for (i = 0; i < 20; i++)
    pi[i] = clone8(i < 8 ? i : 0xA);

  //do_xfer_unchecked_s_d( 1+(UChar*)&pi[2], 2+(UChar*)&pi[12] );
  do_xfer_checked_s_d( 1+(UChar*)&pi[3], 3+(UChar*)&pi[13] );

  for (i = 0; i < 20; i++) 
    printf("%2d%c  %016llx\n", i, ((i & 3) == 0) ? '.' : ' ', pi[i]);

  return 0;
}

#include <assert.h>
#if defined(__APPLE__)
#include <malloc/malloc.h>
#else
#include <malloc.h>
#endif
#include <stdlib.h>
#include <stdio.h>

int main(void)
{
   // Because Memcheck marks any slop as inaccessible, it doesn't round up
   // sizes for malloc_usable_size().
   int* x = malloc(99);

   // DDD: would be better to have a HAVE_MALLOC_USABLE_SIZE variable here
#  if !defined(_AIX) && !defined(__APPLE__)
   assert(99 == malloc_usable_size(x));
   assert( 0 == malloc_usable_size(NULL));
   assert( 0 == malloc_usable_size((void*)0xdeadbeef));
#  endif

   return 0;
}

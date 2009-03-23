char* get_bad_place ( void );
int main ( void )
{
#if defined(__powerpc64__) || defined(_AIX)
   /* on ppc64-linux, a function pointer points to a function
      descriptor, not to the function's entry point.  Hence to get
      uniform behaviour on all supported targets - a jump to an
      unmapped page - the following is needed. */
   unsigned long long int fake_fndescr[3];
   fake_fndescr[0] = (unsigned long long int)get_bad_place();
   fake_fndescr[1] = 0;
   fake_fndescr[2] = 0;
   return ((int(*)(void)) fake_fndescr) ();
#else
   char* p = get_bad_place();
   return ((int(*)(void)) p) ();
#endif
}

#include <sys/mman.h>
#include <assert.h>
#include <unistd.h>

/* map a page, then unmap it, then return that address.  That
   guarantees to give an address which will fault when accessed,
   without making any assumptions about the layout of the address
   space. */

char* get_bad_place ( void )
{
   long pagesz = sysconf(_SC_PAGE_SIZE);
   assert(pagesz == 4096 || pagesz == 65536);
   void* ptr = mmap(0, pagesz, PROT_READ, MAP_ANON|MAP_PRIVATE, -1, 0);
   assert(ptr != (void*)-1);
   int r = munmap(ptr, pagesz);
   assert(r == 0);
   return ptr;
}

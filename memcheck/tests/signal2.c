
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

void sig_hdlr ( int signo ) {
   printf ( "caught sig segv\n" ); exit(1);
}
char* get_bad_place ( void );

int main ( void ) {
   char* badplace;
   printf ( "installing sig handler\n" );
   signal(SIGSEGV, sig_hdlr);
   printf ( "doing bad thing\n" );
   badplace = get_bad_place();
   *(int*)badplace = 0;
   printf ( "exited normally ?!\n" );
   return 0;
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

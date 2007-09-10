
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>

/* Simple test program, no race.  Parent writes atomically to a counter
   whilst child reads it.  When counter reaches a prearranged value, 
   child joins back to parent.  Parent (writer) uses hardware bus lock;
   child is only reading and so does not need to use a bus lock. */


#undef PLAT_x86_linux
#undef PLAT_amd64_linux
#undef PLAT_ppc32_linux
#undef PLAT_ppc64_linux
#undef PLAT_ppc32_aix5
#undef PLAT_ppc64_aix5

#if !defined(_AIX) && defined(__i386__)
#  define PLAT_x86_linux 1
#elif !defined(_AIX) && defined(__x86_64__)
#  define PLAT_amd64_linux 1
#elif !defined(_AIX) && defined(__powerpc__) && !defined(__powerpc64__)
#  define PLAT_ppc32_linux 1
#elif !defined(_AIX) && defined(__powerpc__) && defined(__powerpc64__)
#  define PLAT_ppc64_linux 1
#elif defined(_AIX) && defined(__64BIT__)
#  define PLAT_ppc64_aix5 1
#elif defined(_AIX) && !defined(__64BIT__)
#  define PLAT_ppc32_aix5 1
#endif


#if defined(PLAT_amd64_linux)
#  define INC(_lval) \
      __asm__ __volatile__ ( \
      "lock ; incl (%0)" : /*out*/ : /*in*/"r"(&(_lval)) : "memory", "cc" )
#else
#  error "Fix Me for this platform"
#endif



#define LIMIT 10

int x = 0;

void* child_fn ( void* arg )
{
   int q = 0;
   int oldx = 0;
   while (1) {
      q = x == LIMIT;
      if (x != oldx) {
         oldx = x;
         printf("child: new value %d\n", oldx);
      }
      if (q) break;
   }
   return NULL;
}

int main ( void )
{
   pthread_t child;
   int i;

   if (pthread_create(&child, NULL, child_fn, NULL)) {
      perror("pthread_create");
      exit(1);
   }

   for (i = 0; i < LIMIT; i++) {
      INC(x);
      /* Not really necessary, but just gives the child a chance
	 to run too. */
      sched_yield();
   }

   if (pthread_join(child, NULL)) {
      perror("pthread join");
      exit(1);
   }

   return 0;
}

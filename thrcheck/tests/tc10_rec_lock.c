
/* Do simple things with a recursive mutex. */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>



/* glibc 2.3 doesn't appear to supply PTHREAD_MUTEX_RECURSIVE.
   We have to give up. */
#if __GLIBC__ < 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ <= 3)
int main ( void ) {
   printf("This program does not compile on systems "
          "using glibc 2.3 or earlier.\n");
   return 0;
}
#else



#define __USE_UNIX98 1
#include <pthread.h>

void nearly_main ( void )
{
   pthread_mutex_t mx1;
   pthread_mutexattr_t attr;
   int r;

   r = pthread_mutexattr_init( &attr );
   assert(r==0);
   r = pthread_mutexattr_settype( &attr, PTHREAD_MUTEX_RECURSIVE );
   assert(r==0);
   r = pthread_mutex_init( &mx1, &attr );
   assert(r==0);

   fprintf(stderr, "before lock #1\n");
   r = pthread_mutex_lock( &mx1 ); assert(r == 0);
   fprintf(stderr, "before lock #2\n");
   r = pthread_mutex_lock( &mx1 ); assert(r == 0);
   fprintf(stderr, "before lock #3\n");
   r = pthread_mutex_lock( &mx1 ); assert(r == 0);

   fprintf(stderr, "before unlock #1\n");
   r = pthread_mutex_unlock( &mx1 ); assert(r == 0);
   fprintf(stderr, "before unlock #2\n");
   r = pthread_mutex_unlock( &mx1 ); assert(r == 0);
   fprintf(stderr, "before unlock #3\n");
   r = pthread_mutex_unlock( &mx1 ); assert(r == 0);

   fprintf(stderr, "before unlock #4\n");
   r = pthread_mutex_unlock( &mx1 ); /* FAILS: assert(r == 0); */
}

int main ( void )
{
   nearly_main();
   return 0;
}


#endif /* !(glibc 2.3 or earlier) */

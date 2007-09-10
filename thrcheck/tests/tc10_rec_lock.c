
/* Do simple things with a recursive mutex. */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

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

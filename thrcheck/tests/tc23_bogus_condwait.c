
/* Expect 5 errors total (4 re cvs, 1 re exiting w/lock.).
   Tests passing bogus mutexes to pthread_cond_wait. */

#include <pthread.h>
#include <assert.h>
#include <unistd.h>

pthread_mutex_t mx[4];
pthread_cond_t cv;
pthread_rwlock_t rwl;

void* rescue_me ( void* uu )
{
  /* wait for, and unblock, the first wait */
  sleep(1);
  pthread_cond_signal( &cv );

  /* wait for, and unblock, the second wait */
  sleep(1);
  pthread_cond_signal( &cv );

  /* wait for, and unblock, the third wait */
  sleep(1);
  pthread_cond_signal( &cv );

  /* wait for grabber and main, then unblock the fourth wait */
  sleep(1+1);
  pthread_cond_signal( &cv );

  return NULL;
}

void* grab_the_lock ( void* uu )
{
   int r= pthread_mutex_lock( &mx[2] ); assert(!r);
   /* tc correctly complains that the thread is exiting whilst still
      holding a lock.  A bit tricky to fix - we just live with it. */
   return NULL;
}

int main ( void )
{
  int r;
  pthread_t my_rescuer, grabber;

  r= pthread_mutex_init(&mx[0], NULL); assert(!r);
  r= pthread_mutex_init(&mx[1], NULL); assert(!r);
  r= pthread_mutex_init(&mx[2], NULL); assert(!r);
  r= pthread_mutex_init(&mx[3], NULL); assert(!r);

  r= pthread_cond_init(&cv, NULL); assert(!r);
  r= pthread_rwlock_init(&rwl, NULL); assert(!r);

  r= pthread_create( &my_rescuer, NULL, rescue_me, NULL );
  assert(!r);

  /* Do stupid things and hope that rescue_me gets us out of
     trouble */

  /* mx is bogus */
  r= pthread_cond_wait(&cv, (pthread_mutex_t*)(1 + (char*)&mx[0]) );

  /* mx is not locked */
  r= pthread_cond_wait(&cv, &mx[0]);

  /* wrong flavour of lock */
  r= pthread_cond_wait(&cv, (pthread_mutex_t*)&rwl );

  /* mx is held by someone else. */
  r= pthread_create( &grabber, NULL, grab_the_lock, NULL ); assert(!r);
  sleep(1); /* let the grabber get there first */
  r= pthread_cond_wait(&cv, &mx[2] );

  r= pthread_join( my_rescuer, NULL ); assert(!r);
  r= pthread_join( grabber, NULL ); assert(!r);
  return 0;
}


#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <semaphore.h>

/* This is really a test of semaphore handling
   (sem_{init,destroy,post,wait}).  Using semaphores a barrier
   function is created.  Thrcheck does understand the barrier
   semantics implied by the barrier, as pieced together from
   happens-before relationships obtained from the component
   semaphores.  However, it does falsely report one race.  Ah well. */

/* This code is derived from
   gcc-4.3-20071012/libgomp/config/posix/bar.c, which is

   Copyright (C) 2005 Free Software Foundation, Inc.
   Contributed by Richard Henderson <rth@redhat.com>.

   and available under version 2.1 or later of the GNU Lesser General
   Public License.

   Relative to the libgomp sources, the gomp_barrier_t type here has
   an extra semaphore field, xxx.  This is not functionally useful,
   but it is used to create enough extra inter-thread dependencies
   that the barrier-like behaviour of gomp_barrier_t is evident to
   Thrcheck.  There is no other purpose for the .xxx field. */

typedef struct
{
  pthread_mutex_t mutex1;
  pthread_mutex_t mutex2;
  sem_t sem1;
  sem_t sem2;
  unsigned total;
  unsigned arrived;
  sem_t xxx;
} gomp_barrier_t;

typedef long bool;

void
gomp_barrier_init (gomp_barrier_t *bar, unsigned count)
{
  pthread_mutex_init (&bar->mutex1, NULL);
  pthread_mutex_init (&bar->mutex2, NULL);
  sem_init (&bar->sem1, 0, 0);
  sem_init (&bar->sem2, 0, 0);
  sem_init (&bar->xxx,  0, 0);
  bar->total = count;
  bar->arrived = 0;
}

void
gomp_barrier_destroy (gomp_barrier_t *bar)
{
  /* Before destroying, make sure all threads have left the barrier.  */
  pthread_mutex_lock (&bar->mutex1);
  pthread_mutex_unlock (&bar->mutex1);

  pthread_mutex_destroy (&bar->mutex1);
  pthread_mutex_destroy (&bar->mutex2);
  sem_destroy (&bar->sem1);
  sem_destroy (&bar->sem2);
  sem_destroy(&bar->xxx);
}

void
gomp_barrier_reinit (gomp_barrier_t *bar, unsigned count)
{
  pthread_mutex_lock (&bar->mutex1);
  bar->total = count;
  pthread_mutex_unlock (&bar->mutex1);
}

void
gomp_barrier_wait (gomp_barrier_t *bar)
{
  unsigned int n;
  pthread_mutex_lock (&bar->mutex1);

  ++bar->arrived;

  if (bar->arrived == bar->total)
    {
      bar->arrived--;
      n = bar->arrived;
      if (n > 0) 
        {
          { unsigned int i;
            for (i = 0; i < n; i++)
              sem_wait(&bar->xxx); // acquire an obvious dependency from
              // all other threads arriving at the barrier
          }
          // 1 up n times, 2 down once
          // now let all the other threads past the barrier, giving them
          // an obvious dependency with this thread.
          do
            sem_post (&bar->sem1); // 1 up
          while (--n != 0);
          // and wait till the last thread has left
          sem_wait (&bar->sem2); // 2 down
        }
      pthread_mutex_unlock (&bar->mutex1);
      /* Resultat professionnel!  First we made this thread have an
         obvious (Thrcheck-visible) dependency on all other threads
         calling gomp_barrier_wait.  Then, we released them all again,
         so they all have a (visible) dependency on this thread.
         Transitively, the result is that all threads leaving the
         barrier have a a Thrcheck-visible dependency on all threads
         arriving at the barrier.  As required. */
    }
  else
    {
      pthread_mutex_unlock (&bar->mutex1);
      sem_post(&bar->xxx);
      // first N-1 threads wind up waiting here
      sem_wait (&bar->sem1); // 1 down 

      pthread_mutex_lock (&bar->mutex2);
      n = --bar->arrived; /* XXX see below */
      pthread_mutex_unlock (&bar->mutex2);

      if (n == 0)
        sem_post (&bar->sem2); // 2 up
    }
}


/* re XXX, thrcheck reports a race at this point.  It doesn't
   understand that bar->arrived is protected by mutex1 whilst threads
   are arriving at the barrier and by mutex2 whilst they are leaving,
   but not consistently by either of them.  Oh well. */

gomp_barrier_t bar;

void* child ( void* argV )
{
   gomp_barrier_wait( &bar );
   gomp_barrier_wait( &bar );
   gomp_barrier_wait( &bar );
   gomp_barrier_wait( &bar );
   gomp_barrier_wait( &bar );
   gomp_barrier_wait( &bar );
   gomp_barrier_wait( &bar );
   gomp_barrier_wait( &bar );
   return NULL;
}

#define NNN 4

int main (int argc, char *argv[])
{
  int j;
   long i; int res;
   pthread_t thr[NNN];
   fprintf(stderr, "starting\n");

   for (j = 0; j < 1; j++) {
   gomp_barrier_init( &bar, NNN );

   for (i = 0; i < NNN; i++) {
      res = pthread_create( &thr[i], NULL, child, (void*)i );
      assert(!res);
   }

   for (i = 0; i < NNN; i++) {
      res = pthread_join( thr[i], NULL );
      assert(!res);
   }

   gomp_barrier_destroy( &bar );
   }
   fprintf(stderr, "done\n");

   return 0;
}
